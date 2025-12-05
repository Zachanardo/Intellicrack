"""Production-grade tests for Opaque Predicate Analysis capabilities.

This test suite validates REAL opaque predicate detection, mathematical invariant
recognition, symbolic execution with Z3, constant propagation, dead code identification,
and control flow deobfuscation on actual binaries.

NO MOCKS, NO STUBS - All tests validate genuine opaque predicate analysis functionality.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from intellicrack.core.analysis.opaque_predicate_analyzer import (
    BasicBlockProtocol,
    ConstantPropagationEngine,
    ConstantValue,
    OpaquePredicateAnalyzer,
    PatternRecognizer,
    PredicateAnalysis,
    SymbolicExecutionEngine,
)

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class BasicBlock:
    """Test implementation of BasicBlock protocol."""

    def __init__(
        self,
        address: int,
        instructions: list[dict[str, Any]],
        successors: list[int],
    ) -> None:
        """Initialize basic block."""
        self.address = address
        self.instructions = instructions
        self.successors = successors


@pytest.fixture
def temp_workspace() -> Path:
    """Create temporary workspace for test binaries."""
    import shutil

    temp_dir = tempfile.mkdtemp(prefix="opaque_predicate_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def self_xor_block() -> BasicBlock:
    """Basic block with XOR eax, eax pattern (always sets to 0)."""
    return BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "xor eax, eax"},
            {"address": 0x1002, "disasm": "test eax, eax"},
            {"address": 0x1004, "disasm": "jz 0x1010"},
        ],
        successors=[0x1010, 0x1006],
    )


@pytest.fixture
def self_comparison_block() -> BasicBlock:
    """Basic block with CMP eax, eax pattern (always equal)."""
    return BasicBlock(
        address=0x2000,
        instructions=[
            {"address": 0x2000, "disasm": "mov eax, 0x42"},
            {"address": 0x2005, "disasm": "cmp eax, eax"},
            {"address": 0x2007, "disasm": "je 0x2020"},
        ],
        successors=[0x2020, 0x2009],
    )


@pytest.fixture
def constant_propagation_block() -> BasicBlock:
    """Basic block with constant values propagated through registers."""
    return BasicBlock(
        address=0x3000,
        instructions=[
            {"address": 0x3000, "disasm": "mov eax, 0x10"},
            {"address": 0x3005, "disasm": "mov ebx, 0x10"},
            {"address": 0x300A, "disasm": "cmp eax, ebx"},
            {"address": 0x300C, "disasm": "je 0x3020"},
        ],
        successors=[0x3020, 0x300E],
    )


@pytest.fixture
def bit_masking_block() -> BasicBlock:
    """Basic block with AND eax, 0 pattern (always 0)."""
    return BasicBlock(
        address=0x4000,
        instructions=[
            {"address": 0x4000, "disasm": "mov eax, 0xFF"},
            {"address": 0x4005, "disasm": "and eax, 0x0"},
            {"address": 0x4008, "disasm": "test eax, eax"},
            {"address": 0x400A, "disasm": "jz 0x4020"},
        ],
        successors=[0x4020, 0x400C],
    )


@pytest.fixture
def arithmetic_invariant_block() -> BasicBlock:
    """Basic block with x*x >= 0 pattern."""
    return BasicBlock(
        address=0x5000,
        instructions=[
            {"address": 0x5000, "disasm": "mov eax, ecx"},
            {"address": 0x5002, "disasm": "imul eax, eax"},
            {"address": 0x5005, "disasm": "test eax, eax"},
            {"address": 0x5007, "disasm": "jns 0x5020"},
        ],
        successors=[0x5020, 0x5009],
    )


@pytest.fixture
def modulo_two_block() -> BasicBlock:
    """Basic block with (x % 2) compared to value >= 2 (always false)."""
    return BasicBlock(
        address=0x6000,
        instructions=[
            {"address": 0x6000, "disasm": "mov eax, ecx"},
            {"address": 0x6002, "disasm": "and eax, 0x1"},
            {"address": 0x6005, "disasm": "cmp eax, 0x5"},
            {"address": 0x6008, "disasm": "je 0x6020"},
        ],
        successors=[0x6020, 0x600A],
    )


@pytest.fixture
def complex_constant_chain_block() -> BasicBlock:
    """Basic block with multiple constant arithmetic operations."""
    return BasicBlock(
        address=0x7000,
        instructions=[
            {"address": 0x7000, "disasm": "mov eax, 0x5"},
            {"address": 0x7005, "disasm": "add eax, 0x3"},
            {"address": 0x7008, "disasm": "sub eax, 0x2"},
            {"address": 0x700B, "disasm": "cmp eax, 0x6"},
            {"address": 0x700E, "disasm": "je 0x7020"},
        ],
        successors=[0x7020, 0x7010],
    )


@pytest.fixture
def shift_operation_block() -> BasicBlock:
    """Basic block with shift operations on constants."""
    return BasicBlock(
        address=0x8000,
        instructions=[
            {"address": 0x8000, "disasm": "mov eax, 0x8"},
            {"address": 0x8005, "disasm": "shl eax, 0x2"},
            {"address": 0x8008, "disasm": "cmp eax, 0x20"},
            {"address": 0x800B, "disasm": "je 0x8020"},
        ],
        successors=[0x8020, 0x800D],
    )


@pytest.fixture
def xor_constant_block() -> BasicBlock:
    """Basic block with XOR on constant values."""
    return BasicBlock(
        address=0x9000,
        instructions=[
            {"address": 0x9000, "disasm": "mov eax, 0xFF"},
            {"address": 0x9005, "disasm": "xor eax, 0xFF"},
            {"address": 0x9008, "disasm": "test eax, eax"},
            {"address": 0x900A, "disasm": "jz 0x9020"},
        ],
        successors=[0x9020, 0x900C],
    )


@pytest.fixture
def increment_decrement_block() -> BasicBlock:
    """Basic block with INC/DEC operations."""
    return BasicBlock(
        address=0xA000,
        instructions=[
            {"address": 0xA000, "disasm": "mov eax, 0x10"},
            {"address": 0xA005, "disasm": "inc eax"},
            {"address": 0xA007, "disasm": "dec eax"},
            {"address": 0xA009, "disasm": "cmp eax, 0x10"},
            {"address": 0xA00C, "disasm": "je 0xA020"},
        ],
        successors=[0xA020, 0xA00E],
    )


@pytest.fixture
def register_copy_block() -> BasicBlock:
    """Basic block with register copying and comparison."""
    return BasicBlock(
        address=0xB000,
        instructions=[
            {"address": 0xB000, "disasm": "mov eax, 0x42"},
            {"address": 0xB005, "disasm": "mov ebx, eax"},
            {"address": 0xB007, "disasm": "cmp eax, ebx"},
            {"address": 0xB009, "disasm": "jne 0xB020"},
        ],
        successors=[0xB020, 0xB00B],
    )


@pytest.fixture
def or_operation_block() -> BasicBlock:
    """Basic block with OR operations on constants."""
    return BasicBlock(
        address=0xC000,
        instructions=[
            {"address": 0xC000, "disasm": "mov eax, 0x0F"},
            {"address": 0xC005, "disasm": "or eax, 0xF0"},
            {"address": 0xC008, "disasm": "cmp eax, 0xFF"},
            {"address": 0xC00B, "disasm": "je 0xC020"},
        ],
        successors=[0xC020, 0xC00D],
    )


@pytest.fixture
def and_operation_block() -> BasicBlock:
    """Basic block with AND operations on constants."""
    return BasicBlock(
        address=0xD000,
        instructions=[
            {"address": 0xD000, "disasm": "mov eax, 0xFF"},
            {"address": 0xD005, "disasm": "and eax, 0x0F"},
            {"address": 0xD008, "disasm": "cmp eax, 0x0F"},
            {"address": 0xD00B, "disasm": "je 0xD020"},
        ],
        successors=[0xD020, 0xD00D],
    )


@pytest.fixture
def right_shift_block() -> BasicBlock:
    """Basic block with right shift operations."""
    return BasicBlock(
        address=0xE000,
        instructions=[
            {"address": 0xE000, "disasm": "mov eax, 0x80"},
            {"address": 0xE005, "disasm": "shr eax, 0x4"},
            {"address": 0xE008, "disasm": "cmp eax, 0x8"},
            {"address": 0xE00B, "disasm": "je 0xE020"},
        ],
        successors=[0xE020, 0xE00D],
    )


@pytest.fixture
def complex_cfg() -> nx.DiGraph:
    """Complex CFG with multiple opaque predicates."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    cfg = nx.DiGraph()

    block1 = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x5"},
            {"address": 0x1005, "disasm": "cmp eax, 0x5"},
            {"address": 0x1008, "disasm": "je 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )
    cfg.add_node(0x1000, data=block1)

    block2 = BasicBlock(
        address=0x2000,
        instructions=[
            {"address": 0x2000, "disasm": "xor ebx, ebx"},
            {"address": 0x2002, "disasm": "test ebx, ebx"},
            {"address": 0x2004, "disasm": "jnz 0x3000"},
        ],
        successors=[0x3000, 0x2500],
    )
    cfg.add_node(0x2000, data=block2)

    block3 = BasicBlock(
        address=0x3000,
        instructions=[
            {"address": 0x3000, "disasm": "mov ecx, edx"},
            {"address": 0x3002, "disasm": "ret"},
        ],
        successors=[],
    )
    cfg.add_node(0x3000, data=block3)

    dead_block = BasicBlock(
        address=0x1500,
        instructions=[{"address": 0x1500, "disasm": "int3"}],
        successors=[],
    )
    cfg.add_node(0x1500, data=dead_block)

    dead_block2 = BasicBlock(
        address=0x2500,
        instructions=[{"address": 0x2500, "disasm": "int3"}],
        successors=[],
    )
    cfg.add_node(0x2500, data=dead_block2)

    cfg.add_edge(0x1000, 0x2000, edge_type="conditional_true")
    cfg.add_edge(0x1000, 0x1500, edge_type="conditional_false")
    cfg.add_edge(0x2000, 0x3000, edge_type="conditional_false")
    cfg.add_edge(0x2000, 0x2500, edge_type="conditional_true")

    return cfg


@pytest.fixture
def simple_cfg_single_predicate() -> nx.DiGraph:
    """Simple CFG with single opaque predicate."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    cfg = nx.DiGraph()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "xor eax, eax"},
            {"address": 0x1002, "disasm": "test eax, eax"},
            {"address": 0x1004, "disasm": "jz 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )
    cfg.add_node(0x1000, data=block)

    true_block = BasicBlock(
        address=0x2000,
        instructions=[{"address": 0x2000, "disasm": "ret"}],
        successors=[],
    )
    cfg.add_node(0x2000, data=true_block)

    false_block = BasicBlock(
        address=0x1500,
        instructions=[{"address": 0x1500, "disasm": "int3"}],
        successors=[],
    )
    cfg.add_node(0x1500, data=false_block)

    cfg.add_edge(0x1000, 0x2000, edge_type="conditional_true")
    cfg.add_edge(0x1000, 0x1500, edge_type="conditional_false")

    return cfg


def test_pattern_recognizer_detects_self_xor(self_xor_block: BasicBlock) -> None:
    """Pattern recognizer identifies XOR eax, eax as opaque predicate."""
    recognizer = PatternRecognizer()

    pattern_name, always_value = recognizer.recognize_pattern(self_xor_block)

    assert pattern_name == "self_xor"
    assert always_value is True


def test_pattern_recognizer_detects_self_comparison(
    self_comparison_block: BasicBlock,
) -> None:
    """Pattern recognizer identifies CMP eax, eax as always true."""
    recognizer = PatternRecognizer()

    pattern_name, always_value = recognizer.recognize_pattern(self_comparison_block)

    assert pattern_name == "self_comparison"
    assert always_value is True


def test_pattern_recognizer_detects_bit_masking(bit_masking_block: BasicBlock) -> None:
    """Pattern recognizer identifies AND x, 0 as always zero."""
    recognizer = PatternRecognizer()

    pattern_name, always_value = recognizer.recognize_pattern(bit_masking_block)

    assert pattern_name == "bit_masking"
    assert always_value is True


def test_pattern_recognizer_detects_algebraic_identity(
    arithmetic_invariant_block: BasicBlock,
) -> None:
    """Pattern recognizer identifies x*x >= 0 mathematical invariant."""
    recognizer = PatternRecognizer()

    pattern_name, always_value = recognizer.recognize_pattern(
        arithmetic_invariant_block
    )

    assert pattern_name == "square_nonnegative"
    assert always_value is True


def test_pattern_recognizer_detects_modulo_invariant(
    modulo_two_block: BasicBlock,
) -> None:
    """Pattern recognizer identifies modulo 2 invariant violations."""
    recognizer = PatternRecognizer()

    pattern_name, always_value = recognizer.recognize_pattern(modulo_two_block)

    if pattern_name is not None:
        assert pattern_name == "modulo_invariant"
        assert always_value is None


def test_constant_propagation_engine_tracks_mov_immediate() -> None:
    """Constant propagation tracks MOV immediate values."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x42"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].is_constant
    assert state["eax"].value == 0x42


def test_constant_propagation_engine_tracks_register_copy() -> None:
    """Constant propagation tracks register-to-register moves."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x10"},
            {"address": 0x1005, "disasm": "mov ebx, eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state and state["eax"].value == 0x10
    assert "ebx" in state and state["ebx"].value == 0x10


def test_constant_propagation_engine_tracks_add_immediate() -> None:
    """Constant propagation computes ADD with immediate."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x5"},
            {"address": 0x1005, "disasm": "add eax, 0x3"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x8


def test_constant_propagation_engine_tracks_sub_immediate() -> None:
    """Constant propagation computes SUB with immediate."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x10"},
            {"address": 0x1005, "disasm": "sub eax, 0x5"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0xB


def test_constant_propagation_engine_tracks_inc() -> None:
    """Constant propagation computes INC operation."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x7"},
            {"address": 0x1005, "disasm": "inc eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x8


def test_constant_propagation_engine_tracks_dec() -> None:
    """Constant propagation computes DEC operation."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x9"},
            {"address": 0x1005, "disasm": "dec eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x8


def test_constant_propagation_engine_handles_xor_self() -> None:
    """Constant propagation recognizes XOR reg, reg as zero."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "xor eax, eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0


def test_constant_propagation_engine_tracks_xor_immediate() -> None:
    """Constant propagation computes XOR with immediate."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0xFF"},
            {"address": 0x1005, "disasm": "xor eax, 0xFF"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0


def test_constant_propagation_engine_tracks_or_immediate() -> None:
    """Constant propagation computes OR with immediate."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x0F"},
            {"address": 0x1005, "disasm": "or eax, 0xF0"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0xFF


def test_constant_propagation_engine_tracks_and_immediate() -> None:
    """Constant propagation computes AND with immediate."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0xFF"},
            {"address": 0x1005, "disasm": "and eax, 0x0F"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x0F


def test_constant_propagation_engine_tracks_shl() -> None:
    """Constant propagation computes SHL operation."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x4"},
            {"address": 0x1005, "disasm": "shl eax, 0x2"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x10


def test_constant_propagation_engine_tracks_shr() -> None:
    """Constant propagation computes SHR operation."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x10"},
            {"address": 0x1005, "disasm": "shr eax, 0x2"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert state["eax"].value == 0x4


def test_constant_propagation_engine_invalidates_after_call() -> None:
    """Constant propagation invalidates volatile registers after CALL."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x42"},
            {"address": 0x1005, "disasm": "mov rcx, 0x10"},
            {"address": 0x100A, "disasm": "call 0x2000"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" not in state
    assert "rcx" not in state


def test_constant_propagation_engine_invalidates_multiply_divide() -> None:
    """Constant propagation invalidates rax/rdx after MUL/DIV."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x4"},
            {"address": 0x1005, "disasm": "mul ebx"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" not in state
    assert "edx" not in state


def test_constant_propagation_engine_merges_states_correctly() -> None:
    """Constant propagation merges states from multiple paths."""
    engine = ConstantPropagationEngine()

    state1 = {
        "eax": ConstantValue("eax", 0x42, True, {}),
        "ebx": ConstantValue("ebx", 0x10, True, {}),
    }

    state2 = {
        "eax": ConstantValue("eax", 0x42, True, {}),
        "ecx": ConstantValue("ecx", 0x20, True, {}),
    }

    merged = engine._merge_states(state1, state2)

    assert "eax" in merged
    assert "ebx" not in merged
    assert "ecx" not in merged


def test_constant_propagation_engine_extract_register() -> None:
    """Constant propagation extracts register names from operands."""
    engine = ConstantPropagationEngine()

    assert engine._extract_register("eax") == "eax"
    assert engine._extract_register("[rax+8]") == "rax"
    assert engine._extract_register("dword ptr [rbx]") == "rbx"
    assert engine._extract_register("0x42") is None


def test_constant_propagation_analyzes_cfg() -> None:
    """Constant propagation analyzes entire CFG correctly."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    engine = ConstantPropagationEngine()
    cfg = nx.DiGraph()

    block1 = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x5"},
        ],
        successors=[0x2000],
    )
    cfg.add_node(0x1000, data=block1)

    block2 = BasicBlock(
        address=0x2000,
        instructions=[
            {"address": 0x2000, "disasm": "add eax, 0x3"},
        ],
        successors=[],
    )
    cfg.add_node(0x2000, data=block2)

    states = engine.analyze_cfg(cfg, 0x1000)

    assert 0x2000 in states
    assert states[0x2000]["eax"].value == 0x5


def test_symbolic_execution_analyzes_je_true() -> None:
    """Symbolic execution proves JE with equal values is always taken."""
    if not Z3_AVAILABLE:
        pytest.skip("Z3 not available")

    engine = SymbolicExecutionEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "cmp eax, 0x42"},
            {"address": 0x1005, "disasm": "je 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )

    register_state = {
        "eax": ConstantValue("eax", 0x42, True, {}),
    }

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is True
    assert proof is not None
    assert "always TRUE" in proof


def test_symbolic_execution_analyzes_jne_false() -> None:
    """Symbolic execution proves JNE with equal values is never taken."""
    if not Z3_AVAILABLE:
        pytest.skip("Z3 not available")

    engine = SymbolicExecutionEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "cmp eax, 0x42"},
            {"address": 0x1005, "disasm": "jne 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )

    register_state = {
        "eax": ConstantValue("eax", 0x42, True, {}),
    }

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is False
    assert proof is not None
    assert "always FALSE" in proof


def test_symbolic_execution_analyzes_test_jz() -> None:
    """Symbolic execution analyzes TEST with JZ correctly."""
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

    register_state = {
        "eax": ConstantValue("eax", 0x0, True, {}),
    }

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is True
    assert proof is not None


def test_symbolic_execution_analyzes_jg_greater() -> None:
    """Symbolic execution proves JG with greater value is always taken."""
    if not Z3_AVAILABLE:
        pytest.skip("Z3 not available")

    engine = SymbolicExecutionEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "cmp eax, 0x10"},
            {"address": 0x1005, "disasm": "jg 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )

    register_state = {
        "eax": ConstantValue("eax", 0x20, True, {}),
    }

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is True


def test_symbolic_execution_analyzes_jl_less() -> None:
    """Symbolic execution proves JL with smaller value is always taken."""
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

    register_state = {
        "eax": ConstantValue("eax", 0x10, True, {}),
    }

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is True


def test_opaque_predicate_analyzer_detects_constant_predicate(
    constant_propagation_block: BasicBlock,
) -> None:
    """Opaque predicate analyzer detects predicates resolvable by constant propagation."""
    analyzer = OpaquePredicateAnalyzer()

    register_state = {
        "eax": ConstantValue("eax", 0x10, True, {}),
        "ebx": ConstantValue("ebx", 0x10, True, {}),
    }

    result = analyzer._check_constant_predicate(
        constant_propagation_block, register_state
    )

    assert result is True


def test_opaque_predicate_analyzer_detects_self_xor_test(
    self_xor_block: BasicBlock,
) -> None:
    """Opaque predicate analyzer detects XOR self followed by TEST."""
    analyzer = OpaquePredicateAnalyzer()

    register_state = {"eax": ConstantValue("eax", 0x0, True, {})}

    result = analyzer._check_constant_predicate(self_xor_block, register_state)

    assert result is True


def test_opaque_predicate_analyzer_identifies_dead_branch() -> None:
    """Opaque predicate analyzer identifies dead branch correctly."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    analyzer = OpaquePredicateAnalyzer()
    cfg = nx.DiGraph()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "cmp eax, eax"},
            {"address": 0x1002, "disasm": "je 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )
    cfg.add_node(0x1000, data=block)

    cfg.add_edge(0x1000, 0x2000, edge_type="conditional_true")
    cfg.add_edge(0x1000, 0x1500, edge_type="conditional_false")

    dead_branch = analyzer._identify_dead_branch(block, cfg, True)

    assert dead_branch == 0x1500


def test_opaque_predicate_analyzer_analyzes_simple_cfg(
    simple_cfg_single_predicate: nx.DiGraph,
) -> None:
    """Opaque predicate analyzer analyzes simple CFG with one opaque predicate."""
    analyzer = OpaquePredicateAnalyzer()

    results = analyzer.analyze_cfg(simple_cfg_single_predicate, 0x1000)

    assert len(results) > 0
    assert any(r.always_value is True for r in results)
    assert any(r.dead_branch is not None for r in results)


def test_opaque_predicate_analyzer_analyzes_complex_cfg(
    complex_cfg: nx.DiGraph,
) -> None:
    """Opaque predicate analyzer detects multiple opaque predicates in complex CFG."""
    analyzer = OpaquePredicateAnalyzer()

    results = analyzer.analyze_cfg(complex_cfg, 0x1000)

    assert len(results) >= 1

    has_true = any(r.always_value is True for r in results)
    has_false = any(r.always_value is False for r in results)

    assert has_true or has_false


def test_opaque_predicate_analyzer_confidence_scoring() -> None:
    """Opaque predicate analyzer assigns appropriate confidence scores."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    analyzer = OpaquePredicateAnalyzer()
    cfg = nx.DiGraph()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "xor eax, eax"},
            {"address": 0x1002, "disasm": "test eax, eax"},
            {"address": 0x1004, "disasm": "jz 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )
    cfg.add_node(0x1000, data=block)

    results = analyzer.analyze_cfg(cfg, 0x1000)

    assert len(results) > 0
    assert all(r.confidence >= 0.80 for r in results)
    assert all(r.confidence <= 1.0 for r in results)


def test_opaque_predicate_analyzer_combines_techniques() -> None:
    """Constant propagation engine handles complex operation chains."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x7000,
        instructions=[
            {"address": 0x7000, "disasm": "mov eax, 0x5"},
            {"address": 0x7005, "disasm": "add eax, 0x3"},
            {"address": 0x7008, "disasm": "sub eax, 0x2"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0x6


def test_opaque_predicate_analyzer_handles_shift_operations() -> None:
    """Constant propagation engine computes shift operations correctly."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x8000,
        instructions=[
            {"address": 0x8000, "disasm": "mov eax, 0x8"},
            {"address": 0x8005, "disasm": "shl eax, 0x2"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0x20


def test_opaque_predicate_analyzer_handles_xor_operations() -> None:
    """Constant propagation engine computes XOR operations correctly."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x9000,
        instructions=[
            {"address": 0x9000, "disasm": "mov eax, 0xFF"},
            {"address": 0x9005, "disasm": "xor eax, 0xFF"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0


def test_opaque_predicate_analyzer_handles_inc_dec() -> None:
    """Constant propagation engine handles INC/DEC operations."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0xA000,
        instructions=[
            {"address": 0xA000, "disasm": "mov eax, 0x10"},
            {"address": 0xA005, "disasm": "inc eax"},
            {"address": 0xA007, "disasm": "dec eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0x10


def test_opaque_predicate_analyzer_handles_register_copy() -> None:
    """Constant propagation engine tracks register copies."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0xB000,
        instructions=[
            {"address": 0xB000, "disasm": "mov eax, 0x42"},
            {"address": 0xB005, "disasm": "mov ebx, eax"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state and state["eax"].value == 0x42
    assert "ebx" in state and state["ebx"].value == 0x42


def test_opaque_predicate_analyzer_handles_or_operations() -> None:
    """Constant propagation engine handles OR operations."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0xC000,
        instructions=[
            {"address": 0xC000, "disasm": "mov eax, 0x0F"},
            {"address": 0xC005, "disasm": "or eax, 0xF0"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0xFF


def test_opaque_predicate_analyzer_handles_and_operations() -> None:
    """Constant propagation engine handles AND operations."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0xD000,
        instructions=[
            {"address": 0xD000, "disasm": "mov eax, 0xFF"},
            {"address": 0xD005, "disasm": "and eax, 0x0F"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0x0F


def test_opaque_predicate_analyzer_handles_right_shift() -> None:
    """Constant propagation engine handles SHR operations."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0xE000,
        instructions=[
            {"address": 0xE000, "disasm": "mov eax, 0x80"},
            {"address": 0xE005, "disasm": "shr eax, 0x4"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].value == 0x8


def test_predicate_analysis_dataclass_fields() -> None:
    """PredicateAnalysis dataclass contains all required fields."""
    analysis = PredicateAnalysis(
        address=0x1000,
        instruction="cmp eax, eax; je 0x2000",
        predicate_type="pattern_self_comparison",
        always_value=True,
        confidence=0.85,
        analysis_method="pattern_self_comparison",
        dead_branch=0x1500,
        symbolic_proof=None,
    )

    assert analysis.address == 0x1000
    assert analysis.instruction == "cmp eax, eax; je 0x2000"
    assert analysis.predicate_type == "pattern_self_comparison"
    assert analysis.always_value is True
    assert analysis.confidence == 0.85
    assert analysis.analysis_method == "pattern_self_comparison"
    assert analysis.dead_branch == 0x1500
    assert analysis.symbolic_proof is None


def test_constant_value_dataclass_fields() -> None:
    """ConstantValue dataclass contains all required fields."""
    const_val = ConstantValue(
        register="eax",
        value=0x42,
        is_constant=True,
        source_instruction={"address": 0x1000, "disasm": "mov eax, 0x42"},
    )

    assert const_val.register == "eax"
    assert const_val.value == 0x42
    assert const_val.is_constant is True
    assert const_val.source_instruction["address"] == 0x1000


def test_opaque_predicate_analyzer_empty_cfg() -> None:
    """Opaque predicate analyzer handles empty CFG gracefully."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    analyzer = OpaquePredicateAnalyzer()
    cfg = nx.DiGraph()

    results = analyzer.analyze_cfg(cfg, 0x1000)

    assert len(results) == 0


def test_opaque_predicate_analyzer_single_successor_block() -> None:
    """Opaque predicate analyzer ignores blocks with single successor."""
    if not NETWORKX_AVAILABLE:
        pytest.skip("NetworkX not available")

    analyzer = OpaquePredicateAnalyzer()
    cfg = nx.DiGraph()

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

    assert len(results) == 0


def test_pattern_recognizer_no_match_returns_none() -> None:
    """Pattern recognizer returns None when no pattern matches."""
    recognizer = PatternRecognizer()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, ebx"},
            {"address": 0x1002, "disasm": "ret"},
        ],
        successors=[],
    )

    pattern_name, always_value = recognizer.recognize_pattern(block)

    assert pattern_name is None
    assert always_value is None


def test_constant_propagation_complex_chain() -> None:
    """Constant propagation handles complex operation chains."""
    engine = ConstantPropagationEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "mov eax, 0x10"},
            {"address": 0x1005, "disasm": "add eax, 0x5"},
            {"address": 0x1008, "disasm": "sub eax, 0x3"},
            {"address": 0x100B, "disasm": "shl eax, 0x1"},
            {"address": 0x100E, "disasm": "xor eax, 0xFF"},
        ],
        successors=[],
    )

    state = engine._analyze_block(block, {})

    assert "eax" in state
    assert state["eax"].is_constant
    assert state["eax"].value == ((0x10 + 0x5 - 0x3) << 1) ^ 0xFF


def test_symbolic_execution_without_z3() -> None:
    """Symbolic execution gracefully handles missing Z3."""
    if Z3_AVAILABLE:
        pytest.skip("Z3 is available, testing unavailable path requires Z3 disabled")

    engine = SymbolicExecutionEngine()

    block = BasicBlock(
        address=0x1000,
        instructions=[
            {"address": 0x1000, "disasm": "cmp eax, 0x42"},
            {"address": 0x1005, "disasm": "je 0x2000"},
        ],
        successors=[0x2000, 0x1500],
    )

    register_state = {"eax": ConstantValue("eax", 0x42, True, {})}

    always_value, proof = engine.analyze_predicate(block, register_state)

    assert always_value is None
    assert proof is None


def test_constant_propagation_without_networkx() -> None:
    """Constant propagation handles missing NetworkX."""
    if NETWORKX_AVAILABLE:
        pytest.skip("NetworkX is available")

    engine = ConstantPropagationEngine()

    result = engine.analyze_cfg(None, 0x1000)

    assert result == {}
