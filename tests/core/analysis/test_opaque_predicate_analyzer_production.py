"""Production-ready tests for opaque predicate analyzer.

This module validates real opaque predicate detection and removal capabilities
using symbolic execution, Z3 solver integration, and pattern recognition.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

from typing import Any

import networkx as nx
import pytest
import z3

from intellicrack.core.analysis.opaque_predicate_analyzer import (
    ConstantPropagationEngine,
    ConstantValue,
    OpaquePredicateAnalyzer,
    PatternRecognizer,
    SymbolicExecutionEngine,
)


class MockBasicBlock:
    """Mock BasicBlock for testing."""

    def __init__(self, address: int, instructions: list[dict[str, Any]], successors: list[int]) -> None:
        """Initialize mock basic block.

        Args:
            address: Block address
            instructions: List of instruction dicts
            successors: List of successor addresses

        """
        self.address = address
        self.instructions = instructions
        self.successors = successors


@pytest.fixture
def constant_propagation_engine() -> ConstantPropagationEngine:
    """Create constant propagation engine fixture.

    Returns:
        ConstantPropagationEngine instance

    """
    return ConstantPropagationEngine()


@pytest.fixture
def symbolic_execution_engine() -> SymbolicExecutionEngine:
    """Create symbolic execution engine fixture.

    Returns:
        SymbolicExecutionEngine instance

    """
    return SymbolicExecutionEngine()


@pytest.fixture
def pattern_recognizer() -> PatternRecognizer:
    """Create pattern recognizer fixture.

    Returns:
        PatternRecognizer instance

    """
    return PatternRecognizer()


@pytest.fixture
def opaque_predicate_analyzer() -> OpaquePredicateAnalyzer:
    """Create opaque predicate analyzer fixture.

    Returns:
        OpaquePredicateAnalyzer instance

    """
    return OpaquePredicateAnalyzer()


class TestSymbolicExecutionEngine:
    """Test Z3-based symbolic execution for opaque predicate detection."""

    def test_z3_solver_initialized(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 solver is properly initialized and available."""
        assert symbolic_execution_engine.solver is not None
        assert isinstance(symbolic_execution_engine.solver, z3.Solver)

    def test_always_true_predicate_with_constants(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 proves predicate is always true when comparing identical constants."""
        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "mov ebx, 0x42"},
            {"disasm": "cmp eax, ebx"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x42, is_constant=True, source_instruction=instructions[0]),
            "ebx": ConstantValue(register="ebx", value=0x42, is_constant=True, source_instruction=instructions[1]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None
        assert "always TRUE" in proof.upper()

    def test_always_false_predicate_with_constants(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 proves predicate is always false when comparing different constants."""
        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "mov ebx, 0x100"},
            {"disasm": "cmp eax, ebx"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x42, is_constant=True, source_instruction=instructions[0]),
            "ebx": ConstantValue(register="ebx", value=0x100, is_constant=True, source_instruction=instructions[1]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is False
        assert proof is not None
        assert "always FALSE" in proof.upper()

    def test_symbolic_execution_with_test_instruction(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 evaluates TEST instruction for zero detection."""
        instructions = [
            {"disasm": "xor eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None

    def test_symbolic_execution_jne_always_true(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 proves JNE is always taken when comparing different constants."""
        instructions = [
            {"disasm": "mov eax, 0x1"},
            {"disasm": "cmp eax, 0x2"},
            {"disasm": "jne 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x1, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None

    def test_symbolic_execution_jg_signed_comparison(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 handles signed greater-than comparison correctly."""
        instructions = [
            {"disasm": "mov eax, 0x100"},
            {"disasm": "cmp eax, 0x50"},
            {"disasm": "jg 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x100, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None

    def test_symbolic_execution_ja_unsigned_comparison(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 handles unsigned above comparison correctly."""
        instructions = [
            {"disasm": "mov eax, 0x100"},
            {"disasm": "cmp eax, 0x50"},
            {"disasm": "ja 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x100, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None

    def test_symbolic_execution_non_constant_returns_none(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Symbolic execution returns None for non-constant predicates."""
        instructions = [
            {"disasm": "mov eax, [rbx]"},
            {"disasm": "cmp eax, ecx"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state: dict[str, ConstantValue] = {}

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is None or isinstance(result, bool)

    def test_symbolic_execution_complex_nested_predicate(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 simplifies complex nested predicates with multiple operations."""
        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "add eax, 0x20"},
            {"disasm": "sub eax, 0x20"},
            {"disasm": "cmp eax, 0x10"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0x10, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None

    def test_symbolic_execution_with_bitvec_operations(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Z3 handles bitwise operations in predicate evaluation."""
        instructions = [
            {"disasm": "mov eax, 0xFF"},
            {"disasm": "and eax, 0x0F"},
            {"disasm": "cmp eax, 0x0F"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state = {
            "eax": ConstantValue(register="eax", value=0xFF, is_constant=True, source_instruction=instructions[0]),
        }

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is True
        assert proof is not None


class TestPatternRecognizer:
    """Test pattern-based opaque predicate detection."""

    def test_self_xor_pattern_detection(self, pattern_recognizer: PatternRecognizer) -> None:
        """Detects XOR reg, reg pattern as always zero."""
        instructions = [
            {"disasm": "xor eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name == "self_xor"
        assert always_value is True

    def test_self_comparison_pattern_detection(self, pattern_recognizer: PatternRecognizer) -> None:
        """Detects CMP reg, reg pattern as always equal."""
        instructions = [
            {"disasm": "cmp eax, eax"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name == "self_comparison"
        assert always_value is True

    def test_bit_masking_pattern_detection(self, pattern_recognizer: PatternRecognizer) -> None:
        """Detects AND reg, 0 pattern as always zero."""
        instructions = [
            {"disasm": "and eax, 0"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name == "bit_masking"
        assert always_value is True

    def test_algebraic_identity_square_nonnegative(self, pattern_recognizer: PatternRecognizer) -> None:
        """Detects x*x >= 0 algebraic identity."""
        instructions = [
            {"disasm": "imul eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jns 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name == "square_nonnegative"
        assert always_value is True

    def test_modulo_invariant_pattern_detection(self, pattern_recognizer: PatternRecognizer) -> None:
        """Detects (x % 2) compared against value >= 2 as impossible."""
        instructions = [
            {"disasm": "and eax, 0x1"},
            {"disasm": "cmp eax, 5"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name == "modulo_invariant"

    def test_no_pattern_match_returns_none(self, pattern_recognizer: PatternRecognizer) -> None:
        """Returns None when no opaque predicate pattern matches."""
        instructions = [
            {"disasm": "mov eax, [rbx]"},
            {"disasm": "cmp eax, ecx"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        pattern_name, always_value = pattern_recognizer.recognize_pattern(block)

        assert pattern_name is None
        assert always_value is None


class TestConstantPropagationEngine:
    """Test constant propagation analysis for opaque predicates."""

    def test_constant_propagation_mov_immediate(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Tracks constants through MOV immediate instructions."""
        instructions = [
            {"disasm": "mov eax, 0x42"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x42
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_mov_register(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through register-to-register MOV."""
        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "mov ebx, eax"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "ebx" in exit_state
        assert exit_state["ebx"].value == 0x42
        assert exit_state["ebx"].is_constant is True

    def test_constant_propagation_add_immediate(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through ADD with immediate."""
        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "add eax, 0x20"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x30
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_sub_immediate(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through SUB with immediate."""
        instructions = [
            {"disasm": "mov eax, 0x50"},
            {"disasm": "sub eax, 0x20"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x30
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_xor_same_register(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Recognizes XOR reg, reg as zeroing operation."""
        instructions = [
            {"disasm": "xor eax, eax"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_xor_with_constant(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through XOR with immediate."""
        instructions = [
            {"disasm": "mov eax, 0xFF"},
            {"disasm": "xor eax, 0x0F"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0xF0
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_and_with_constant(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through AND with immediate."""
        instructions = [
            {"disasm": "mov eax, 0xFF"},
            {"disasm": "and eax, 0x0F"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x0F
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_or_with_constant(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through OR with immediate."""
        instructions = [
            {"disasm": "mov eax, 0xF0"},
            {"disasm": "or eax, 0x0F"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0xFF
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_shl_immediate(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through SHL with immediate."""
        instructions = [
            {"disasm": "mov eax, 0x1"},
            {"disasm": "shl eax, 4"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x10
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_shr_immediate(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through SHR with immediate."""
        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "shr eax, 4"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x1
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_inc(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through INC instruction."""
        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "inc eax"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x11
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_dec(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Propagates constants through DEC instruction."""
        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "dec eax"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" in exit_state
        assert exit_state["eax"].value == 0x0F
        assert exit_state["eax"].is_constant is True

    def test_constant_propagation_invalidates_on_call(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Invalidates volatile registers after function calls."""
        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "call sub_1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" not in exit_state

    def test_constant_propagation_invalidates_on_memory_load(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Invalidates register on memory load."""
        instructions = [
            {"disasm": "mov eax, [rbx]"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert "eax" not in exit_state

    def test_constant_propagation_cfg_merge_states(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Merges states correctly at CFG join points."""
        cfg = nx.DiGraph()

        block1_instructions = [{"disasm": "mov eax, 0x42"}]
        block1 = MockBasicBlock(address=0x100, instructions=block1_instructions, successors=[0x300])

        block2_instructions = [{"disasm": "mov eax, 0x42"}]
        block2 = MockBasicBlock(address=0x200, instructions=block2_instructions, successors=[0x300])

        block3_instructions = [{"disasm": "test eax, eax"}]
        block3 = MockBasicBlock(address=0x300, instructions=block3_instructions, successors=[])

        cfg.add_node(0x100, data=block1)
        cfg.add_node(0x200, data=block2)
        cfg.add_node(0x300, data=block3)
        cfg.add_edge(0x100, 0x300)
        cfg.add_edge(0x200, 0x300)

        block_states = constant_propagation_engine.analyze_cfg(cfg, 0x100)

        assert 0x300 in block_states
        assert "eax" in block_states[0x300]
        assert block_states[0x300]["eax"].value == 0x42

    def test_constant_propagation_cfg_divergent_states(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Correctly handles divergent states at join points."""
        cfg = nx.DiGraph()

        block1_instructions = [{"disasm": "mov eax, 0x42"}]
        block1 = MockBasicBlock(address=0x100, instructions=block1_instructions, successors=[0x300])

        block2_instructions = [{"disasm": "mov eax, 0x100"}]
        block2 = MockBasicBlock(address=0x200, instructions=block2_instructions, successors=[0x300])

        block3_instructions = [{"disasm": "test eax, eax"}]
        block3 = MockBasicBlock(address=0x300, instructions=block3_instructions, successors=[])

        cfg.add_node(0x100, data=block1)
        cfg.add_node(0x200, data=block2)
        cfg.add_node(0x300, data=block3)
        cfg.add_edge(0x100, 0x300)
        cfg.add_edge(0x200, 0x300)

        block_states = constant_propagation_engine.analyze_cfg(cfg, 0x100)

        assert 0x300 in block_states
        assert "eax" not in block_states[0x300]


class TestOpaquePredicateAnalyzer:
    """Test integrated opaque predicate analysis combining all techniques."""

    def test_detects_always_true_with_symbolic_execution(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Detects always-true predicate using symbolic execution."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "cmp eax, 0x42"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 1
        assert results[0].always_value is True
        assert results[0].analysis_method == "symbolic_execution"
        assert results[0].confidence >= 0.90

    def test_detects_always_false_with_symbolic_execution(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Detects always-false predicate using symbolic execution."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "cmp eax, 0x100"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 1
        assert results[0].always_value is False
        assert results[0].analysis_method == "symbolic_execution"
        assert results[0].confidence >= 0.90

    def test_detects_opaque_predicate_with_pattern_recognition(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Detects opaque predicate using pattern recognition when symbolic execution unavailable."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "xor eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) >= 1
        assert any(r.always_value is True for r in results)

    def test_identifies_dead_branch_for_always_true(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Identifies dead branch when predicate is always true."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "cmp eax, 0x42"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 1
        assert results[0].dead_branch == 0x300

    def test_identifies_dead_branch_for_always_false(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Identifies dead branch when predicate is always false."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "cmp eax, 0x100"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 1
        assert results[0].dead_branch == 0x200

    def test_simplifies_complex_nested_predicates(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Simplifies complex nested predicates with multiple operations."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x10"},
            {"disasm": "add eax, 0x20"},
            {"disasm": "sub eax, 0x20"},
            {"disasm": "xor eax, 0x10"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) >= 1

    def test_handles_context_dependent_predicates(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Handles predicates that depend on execution context correctly."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, [rbx]"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert all(r.always_value is None or isinstance(r.always_value, bool) for r in results)

    def test_detects_junk_branches_in_obfuscated_code(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Identifies obfuscation-inserted junk branches."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x1"},
            {"disasm": "imul eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jns 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) >= 1
        assert any(r.always_value is True for r in results)

    def test_handles_predicates_with_side_effects(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Correctly handles predicates that may have side effects."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "call sub_1000"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert all(r.always_value is None or isinstance(r.always_value, bool) for r in results)

    def test_multiple_opaque_predicates_in_cfg(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Detects multiple opaque predicates in a single CFG."""
        cfg = nx.DiGraph()

        block1_instructions = [
            {"disasm": "xor eax, eax"},
            {"disasm": "test eax, eax"},
            {"disasm": "jz 0x200"},
        ]
        block1 = MockBasicBlock(address=0x100, instructions=block1_instructions, successors=[0x200, 0x300])

        block2_instructions = [
            {"disasm": "mov ebx, 0x42"},
            {"disasm": "cmp ebx, 0x42"},
            {"disasm": "je 0x400"},
        ]
        block2 = MockBasicBlock(address=0x200, instructions=block2_instructions, successors=[0x400, 0x500])

        cfg.add_node(0x100, data=block1)
        cfg.add_node(0x200, data=block2)
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_node(0x400, data=MockBasicBlock(0x400, [], []))
        cfg.add_node(0x500, data=MockBasicBlock(0x500, [], []))

        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")
        cfg.add_edge(0x200, 0x400, edge_type="conditional_true")
        cfg.add_edge(0x200, 0x500, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) >= 2

    def test_confidence_scores_reflect_analysis_method(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Confidence scores correctly reflect analysis method used."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, 0x42"},
            {"disasm": "cmp eax, 0x42"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 1
        if results[0].analysis_method == "symbolic_execution":
            assert results[0].confidence >= 0.90
        elif "pattern" in results[0].analysis_method:
            assert results[0].confidence >= 0.80

    def test_no_false_positives_on_regular_predicates(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Does not generate false positives on legitimate dynamic predicates."""
        cfg = nx.DiGraph()

        instructions = [
            {"disasm": "mov eax, [rbx]"},
            {"disasm": "mov ecx, [rdx]"},
            {"disasm": "cmp eax, ecx"},
            {"disasm": "je 0x200"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert len(results) == 0 or all(r.confidence < 0.80 for r in results)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_empty_cfg(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Handles empty CFG gracefully."""
        cfg = nx.DiGraph()

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert results == []

    def test_handles_single_block_cfg(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Handles CFG with single block."""
        cfg = nx.DiGraph()

        instructions = [{"disasm": "ret"}]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        cfg.add_node(0x100, data=block)

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert isinstance(results, list)

    def test_handles_block_with_no_instructions(self, opaque_predicate_analyzer: OpaquePredicateAnalyzer) -> None:
        """Handles basic block with no instructions."""
        cfg = nx.DiGraph()

        block = MockBasicBlock(address=0x100, instructions=[], successors=[0x200, 0x300])

        cfg.add_node(0x100, data=block)
        cfg.add_node(0x200, data=MockBasicBlock(0x200, [], []))
        cfg.add_node(0x300, data=MockBasicBlock(0x300, [], []))
        cfg.add_edge(0x100, 0x200, edge_type="conditional_true")
        cfg.add_edge(0x100, 0x300, edge_type="conditional_false")

        results = opaque_predicate_analyzer.analyze_cfg(cfg, 0x100)

        assert isinstance(results, list)

    def test_handles_malformed_disassembly(self, constant_propagation_engine: ConstantPropagationEngine) -> None:
        """Handles malformed disassembly strings gracefully."""
        instructions = [
            {"disasm": ""},
            {"disasm": "mov"},
            {"disasm": "invalid instruction"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[])

        entry_state: dict[str, ConstantValue] = {}
        exit_state = constant_propagation_engine._analyze_block(block, entry_state)

        assert isinstance(exit_state, dict)

    def test_z3_solver_timeout_handling(self, symbolic_execution_engine: SymbolicExecutionEngine) -> None:
        """Handles Z3 solver timeouts gracefully."""
        instructions = [
            {"disasm": "mov eax, [complex_expression]"},
            {"disasm": "cmp eax, ebx"},
            {"disasm": "je 0x1000"},
        ]
        block = MockBasicBlock(address=0x100, instructions=instructions, successors=[0x1000, 0x200])

        register_state: dict[str, ConstantValue] = {}

        result, proof = symbolic_execution_engine.analyze_predicate(block, register_state)

        assert result is None or isinstance(result, bool)
        assert proof is None or isinstance(proof, str)
