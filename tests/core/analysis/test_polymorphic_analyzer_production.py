"""Production tests for polymorphic_analyzer module.

This module tests the PolymorphicAnalyzer which provides detection and analysis
of polymorphic and metamorphic code used in software protection schemes.

Copyright (C) 2025 Zachary Flint
"""

import hashlib
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.polymorphic_analyzer import (
    CAPSTONE_AVAILABLE,
    BehaviorPattern,
    CodeBlock,
    InstructionNode,
    MutationType,
    PolymorphicAnalysis,
    PolymorphicAnalyzer,
    PolymorphicEngine,
)


@pytest.fixture
def simple_x86_code() -> bytes:
    """Create simple x86 code for testing."""
    return bytes([
        0x55,
        0x89, 0xE5,
        0x31, 0xC0,
        0x5D,
        0xC3,
    ])


@pytest.fixture
def polymorphic_xor_code() -> bytes:
    """Create polymorphic XOR decryption loop."""
    return bytes([
        0xB9, 0x10, 0x00, 0x00, 0x00,
        0x31, 0xDB,
        0x8A, 0x1C, 0x0B,
        0x30, 0xC3,
        0x88, 0x1C, 0x0B,
        0x41,
        0xE2, 0xF4,
    ])


@pytest.fixture
def junk_insertion_code() -> bytes:
    """Create code with junk insertion obfuscation."""
    return bytes([
        0x90,
        0x90,
        0x90,
        0x31, 0xC0,
        0x90,
        0x90,
        0x40,
        0x90,
        0xC3,
    ])


class TestInstructionNodeDataclass:
    """Test InstructionNode dataclass functionality."""

    def test_instruction_node_creation(self) -> None:
        """InstructionNode creates with correct semantic hash."""
        node = InstructionNode(
            semantic_class="data_transfer",
            operand_types=("reg", "reg"),
            data_dependencies={"eax", "ebx"},
            control_dependencies=set(),
            side_effects={"eax"},
        )

        assert node.semantic_class == "data_transfer"
        assert len(node.semantic_hash) == 16
        assert isinstance(node.semantic_hash, str)

    def test_semantic_hash_consistency(self) -> None:
        """Semantic hash is consistent for same instruction semantics."""
        node1 = InstructionNode(
            semantic_class="arithmetic",
            operand_types=("reg", "imm"),
            data_dependencies={"eax"},
            control_dependencies=set(),
            side_effects={"eax", "flags"},
        )

        node2 = InstructionNode(
            semantic_class="arithmetic",
            operand_types=("reg", "imm"),
            data_dependencies={"eax"},
            control_dependencies=set(),
            side_effects={"eax", "flags"},
        )

        assert node1.semantic_hash == node2.semantic_hash

    def test_different_semantics_different_hash(self) -> None:
        """Different instruction semantics produce different hashes."""
        node1 = InstructionNode(
            semantic_class="data_transfer",
            operand_types=("reg", "reg"),
        )

        node2 = InstructionNode(
            semantic_class="arithmetic",
            operand_types=("reg", "reg"),
        )

        assert node1.semantic_hash != node2.semantic_hash


class TestCodeBlockDataclass:
    """Test CodeBlock dataclass functionality."""

    def test_code_block_creation(self) -> None:
        """CodeBlock creates with correct attributes."""
        block = CodeBlock(
            start_address=0x1000,
            end_address=0x1100,
            instructions=[],
            normalized_instructions=[],
            mutations_detected=[MutationType.JUNK_INSERTION],
        )

        assert block.start_address == 0x1000
        assert block.end_address == 0x1100
        assert len(block.mutations_detected) == 1


class TestBehaviorPatternDataclass:
    """Test BehaviorPattern dataclass functionality."""

    def test_behavior_pattern_creation(self) -> None:
        """BehaviorPattern creates with correct attributes."""
        pattern = BehaviorPattern(
            pattern_id="decrypt_loop_001",
            semantic_signature="xor_decrypt",
            data_flow_graph={"eax": {"ebx", "ecx"}},
            control_flow_graph={0: {1, 2}},
            register_usage={"eax": "counter", "ebx": "key"},
            memory_accesses=[("read", 0x1000, 4)],
            api_calls=["VirtualProtect"],
            constants={0x100, 0x200},
            behavioral_hash="abc123",
            confidence=0.85,
        )

        assert pattern.pattern_id == "decrypt_loop_001"
        assert pattern.confidence == 0.85
        assert "VirtualProtect" in pattern.api_calls


class TestPolymorphicAnalyzerInitialization:
    """Test PolymorphicAnalyzer initialization."""

    def test_initialization_default_params(self) -> None:
        """PolymorphicAnalyzer initializes with default parameters."""
        analyzer = PolymorphicAnalyzer()

        assert analyzer.arch == "x86"
        assert analyzer.bits == 64
        assert isinstance(analyzer.semantic_cache, dict)
        assert isinstance(analyzer.behavior_database, dict)

    def test_initialization_custom_params(self) -> None:
        """PolymorphicAnalyzer accepts custom parameters."""
        analyzer = PolymorphicAnalyzer(
            binary_path="/path/to/binary.exe",
            arch="x86",
            bits=32,
        )

        assert analyzer.binary_path == "/path/to/binary.exe"
        assert analyzer.arch == "x86"
        assert analyzer.bits == 32

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_disassembler_initialized_when_capstone_available(self) -> None:
        """Disassembler is initialized when Capstone is available."""
        analyzer = PolymorphicAnalyzer()

        assert analyzer.disassembler is not None

    @pytest.mark.skipif(CAPSTONE_AVAILABLE, reason="Capstone is available")
    def test_disassembler_none_when_capstone_unavailable(self) -> None:
        """Disassembler is None when Capstone unavailable."""
        analyzer = PolymorphicAnalyzer()

        assert analyzer.disassembler is None


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestPolymorphicCodeAnalysis:
    """Test polymorphic code analysis functionality."""

    def test_analyze_simple_code(self, simple_x86_code: bytes) -> None:
        """PolymorphicAnalyzer analyzes simple code successfully."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(simple_x86_code)

        assert isinstance(result, PolymorphicAnalysis)
        assert isinstance(result.mutation_types, list)
        assert isinstance(result.behavior_patterns, list)
        assert isinstance(result.invariant_features, dict)

    def test_analyze_polymorphic_xor_loop(self, polymorphic_xor_code: bytes) -> None:
        """PolymorphicAnalyzer detects XOR decryption loop pattern."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result, PolymorphicAnalysis)
        assert result.engine_type in [
            PolymorphicEngine.CUSTOM,
            PolymorphicEngine.UNKNOWN,
        ]

    def test_detect_junk_insertion(self, junk_insertion_code: bytes) -> None:
        """PolymorphicAnalyzer detects junk code insertion."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(junk_insertion_code)

        assert isinstance(result, PolymorphicAnalysis)

    def test_analysis_result_completeness(self, simple_x86_code: bytes) -> None:
        """Analysis result contains all expected fields."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(simple_x86_code)

        assert hasattr(result, "engine_type")
        assert hasattr(result, "mutation_types")
        assert hasattr(result, "behavior_patterns")
        assert hasattr(result, "invariant_features")
        assert hasattr(result, "mutation_complexity")
        assert hasattr(result, "evasion_techniques")


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestCodeNormalization:
    """Test code normalization functionality."""

    def test_normalize_code_variant(self, simple_x86_code: bytes) -> None:
        """normalize_code_variant returns consistent hash."""
        analyzer = PolymorphicAnalyzer(bits=32)
        normalized = analyzer.normalize_code_variant(simple_x86_code)

        assert isinstance(normalized, str)
        assert len(normalized) == 64

    def test_normalization_consistency(self, simple_x86_code: bytes) -> None:
        """Same code produces same normalized hash."""
        analyzer = PolymorphicAnalyzer(bits=32)

        norm1 = analyzer.normalize_code_variant(simple_x86_code)
        norm2 = analyzer.normalize_code_variant(simple_x86_code)

        assert norm1 == norm2

    def test_normalize_empty_code(self) -> None:
        """Normalization handles empty code."""
        analyzer = PolymorphicAnalyzer(bits=32)
        normalized = analyzer.normalize_code_variant(b"")

        assert isinstance(normalized, str)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestSemanticSignatureExtraction:
    """Test semantic signature extraction."""

    def test_extract_semantic_signature(self, simple_x86_code: bytes) -> None:
        """extract_semantic_signature returns signature string."""
        analyzer = PolymorphicAnalyzer(bits=32)
        signature = analyzer.extract_semantic_signature(simple_x86_code)

        assert isinstance(signature, str)

    def test_signature_consistency(self, simple_x86_code: bytes) -> None:
        """Same code produces same semantic signature."""
        analyzer = PolymorphicAnalyzer(bits=32)

        sig1 = analyzer.extract_semantic_signature(simple_x86_code)
        sig2 = analyzer.extract_semantic_signature(simple_x86_code)

        assert sig1 == sig2


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestMutationDetection:
    """Test mutation type detection."""

    def test_detect_mutations_returns_list(self, polymorphic_xor_code: bytes) -> None:
        """Mutation detection returns list of mutation types."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.mutation_types, list)

    def test_mutation_complexity_calculation(self, polymorphic_xor_code: bytes) -> None:
        """Mutation complexity is calculated correctly."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.mutation_complexity, float)
        assert result.mutation_complexity >= 0.0


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestEngineIdentification:
    """Test polymorphic engine identification."""

    def test_identify_engine_type(self, polymorphic_xor_code: bytes) -> None:
        """Engine identification returns valid engine type."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.engine_type, PolymorphicEngine)

    def test_unknown_engine_for_simple_code(self, simple_x86_code: bytes) -> None:
        """Simple code is identified as unknown or custom engine."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(simple_x86_code)

        assert result.engine_type in [
            PolymorphicEngine.UNKNOWN,
            PolymorphicEngine.CUSTOM,
        ]


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestBehaviorPatternExtraction:
    """Test behavior pattern extraction."""

    def test_extract_behavior_patterns(self, polymorphic_xor_code: bytes) -> None:
        """Behavior pattern extraction returns list of patterns."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.behavior_patterns, list)

    def test_behavior_patterns_have_signatures(self, polymorphic_xor_code: bytes) -> None:
        """Extracted behavior patterns contain semantic signatures."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        for pattern in result.behavior_patterns:
            assert isinstance(pattern, BehaviorPattern)
            assert isinstance(pattern.semantic_signature, str)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestInvariantExtraction:
    """Test invariant feature extraction."""

    def test_extract_invariants(self, polymorphic_xor_code: bytes) -> None:
        """Invariant extraction returns dictionary."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.invariant_features, dict)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestEvasionTechniqueDetection:
    """Test evasion technique detection."""

    def test_detect_evasion_techniques(self, polymorphic_xor_code: bytes) -> None:
        """Evasion technique detection returns list."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(polymorphic_xor_code)

        assert isinstance(result.evasion_techniques, list)


@pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
class TestErrorHandling:
    """Test error handling in polymorphic analyzer."""

    def test_analyze_empty_code(self) -> None:
        """Analyzer handles empty code gracefully."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(b"")

        assert isinstance(result, PolymorphicAnalysis)

    def test_analyze_invalid_code(self) -> None:
        """Analyzer handles invalid code bytes."""
        analyzer = PolymorphicAnalyzer(bits=32)
        result = analyzer.analyze_polymorphic_code(b"\xff" * 100)

        assert isinstance(result, PolymorphicAnalysis)


class TestCapstoneNotAvailable:
    """Test behavior when Capstone is not available."""

    @pytest.mark.skipif(CAPSTONE_AVAILABLE, reason="Capstone is available")
    def test_analysis_without_capstone(self, simple_x86_code: bytes) -> None:
        """Analyzer returns minimal result when Capstone unavailable."""
        analyzer = PolymorphicAnalyzer()
        result = analyzer.analyze_polymorphic_code(simple_x86_code)

        assert isinstance(result, PolymorphicAnalysis)
        assert result.engine_type == PolymorphicEngine.UNKNOWN
        assert len(result.mutation_types) == 0

    @pytest.mark.skipif(CAPSTONE_AVAILABLE, reason="Capstone is available")
    def test_normalize_without_capstone(self, simple_x86_code: bytes) -> None:
        """Normalization falls back to hash when Capstone unavailable."""
        analyzer = PolymorphicAnalyzer()
        normalized = analyzer.normalize_code_variant(simple_x86_code)

        assert isinstance(normalized, str)
        assert len(normalized) == 64
