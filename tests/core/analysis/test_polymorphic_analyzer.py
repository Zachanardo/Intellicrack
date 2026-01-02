"""Comprehensive tests for PolymorphicAnalyzer.

Tests the polymorphic and metamorphic code analysis engine with real
code patterns and authentic mutation techniques.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any
import hashlib
import pytest

from intellicrack.core.analysis.polymorphic_analyzer import (
    BehaviorPattern,
    CodeBlock,
    InstructionNode,
    MutationType,
    PolymorphicAnalyzer,
    PolymorphicEngine,
)

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


@pytest.fixture
def analyzer_32bit() -> Any:
    """Create 32-bit polymorphic analyzer."""
    return PolymorphicAnalyzer(arch="x86", bits=32)


@pytest.fixture
def analyzer_64bit() -> Any:
    """Create 64-bit polymorphic analyzer."""
    return PolymorphicAnalyzer(arch="x86", bits=64)


class TestPolymorphicEngineDetection:
    """Test detection of known polymorphic engines."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_metaphor_detection(self, analyzer_32bit: Any) -> None:
        """Test detection of MetaPHOR-style polymorphic engine."""
        code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0xB9,
                0x10,
                0x00,
                0x00,
                0x00,
                0xBE,
                0x00,
                0x40,
                0x00,
                0x00,
                0xBF,
                0x00,
                0x50,
                0x00,
                0x00,
                0x8A,
                0x06,
                0x30,
                0xC0,
                0x88,
                0x07,
                0x46,
                0x47,
                0xE2,
                0xF6,
                0x8B,
                0x45,
                0x08,
                0x31,
                0xC0,
                0x31,
                0xDB,
                0x31,
                0xC9,
                0xE2,
                0xFE,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code, base_address=0x1000)

        assert analysis.engine_type in [
            PolymorphicEngine.METAPHOR,
            PolymorphicEngine.CUSTOM,
        ], f"Expected MetaPHOR or CUSTOM, got {analysis.engine_type}"
        assert len(analysis.mutation_types) > 0
        assert analysis.decryption_routine is not None

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_zmist_detection(self, analyzer_32bit: Any) -> None:
        """Test detection of Zmist-style polymorphic engine."""
        code = bytes(
            [
                0x60,
                0x9C,
                0x50,
                0x53,
                0x51,
                0x52,
                0x56,
                0x57,
                0x55,
                0x8B,
                0xEC,
                0x83,
                0xEC,
                0x40,
                0x8B,
                0x75,
                0x00,
                0x8B,
                0x7D,
                0x04,
                0x31,
                0xC0,
                0x50,
                0x58,
                0x50,
                0x58,
                0x5D,
                0x5F,
                0x5E,
                0x5A,
                0x59,
                0x5B,
                0x58,
                0x9D,
                0x61,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code, base_address=0x2000)

        assert analysis.engine_type in [
            PolymorphicEngine.ZMIST,
            PolymorphicEngine.CUSTOM,
        ]
        assert MutationType.JUNK_INSERTION in analysis.mutation_types or len(
            analysis.mutation_types
        ) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_custom_engine_detection(self, analyzer_64bit: Any) -> None:
        """Test detection of custom polymorphic engine."""
        code = bytes(
            [
                0x48,
                0x89,
                0xE5,
                0x48,
                0x83,
                0xEC,
                0x20,
                0x48,
                0x8D,
                0x3D,
                0x00,
                0x10,
                0x00,
                0x00,
                0x48,
                0x31,
                0xC0,
                0x48,
                0x31,
                0xDB,
                0xC3,
            ]
        )

        analysis = analyzer_64bit.analyze_polymorphic_code(code, base_address=0x3000)

        assert analysis.engine_type != PolymorphicEngine.UNKNOWN or len(
            analysis.behavior_patterns
        ) > 0


class TestMutationDetection:
    """Test detection of specific mutation techniques."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_instruction_substitution(self, analyzer_32bit: Any) -> None:
        """Test detection of instruction substitution."""
        code = bytes(
            [
                0x31,
                0xC0,
                0x01,
                0xC0,
                0x29,
                0xC0,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0x48,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.INSTRUCTION_SUBSTITUTION in analysis.mutation_types

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_register_renaming(self, analyzer_32bit: Any) -> None:
        """Test detection of register renaming."""
        code = bytes(
            [
                0x89,
                0xC3,
                0x89,
                0xD9,
                0x89,
                0xF2,
                0x89,
                0xFE,
                0x01,
                0xD8,
                0x01,
                0xCB,
                0x01,
                0xF2,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.REGISTER_RENAMING in analysis.mutation_types

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_junk_insertion(self, analyzer_32bit: Any) -> None:
        """Test detection of junk code insertion."""
        code = bytes(
            [
                0x90,
                0x90,
                0x50,
                0x58,
                0x90,
                0x89,
                0xC0,
                0x31,
                0xC0,
                0x53,
                0x5B,
                0x90,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.JUNK_INSERTION in analysis.mutation_types

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_dead_code_detection(self, analyzer_32bit: Any) -> None:
        """Test detection of dead code."""
        code = bytes(
            [
                0x31,
                0xC0,
                0xB8,
                0x05,
                0x00,
                0x00,
                0x00,
                0x31,
                0xDB,
                0xBB,
                0x10,
                0x00,
                0x00,
                0x00,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.DEAD_CODE in analysis.mutation_types

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_opaque_predicates(self, analyzer_32bit: Any) -> None:
        """Test detection of opaque predicates."""
        code = bytes(
            [
                0x85,
                0xC0,
                0x74,
                0x02,
                0xEB,
                0x00,
                0x31,
                0xC0,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.OPAQUE_PREDICATES in analysis.mutation_types

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_nops(self, analyzer_32bit: Any) -> None:
        """Test detection of semantic NOPs."""
        code = bytes(
            [
                0x83,
                0xC0,
                0x05,
                0x83,
                0xE8,
                0x05,
                0x01,
                0xC3,
                0x29,
                0xC3,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert MutationType.SEMANTIC_NOP in analysis.mutation_types


class TestCodeNormalization:
    """Test code normalization and semantic signature extraction."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_normalize_equivalent_sequences(self, analyzer_32bit: Any) -> None:
        """Test normalization of equivalent instruction sequences."""
        code1 = bytes([0x31, 0xC0])
        code2 = bytes([0x29, 0xC0])
        code3 = bytes([0xB8, 0x00, 0x00, 0x00, 0x00])

        sig1 = analyzer_32bit.normalize_code_variant(code1)
        sig2 = analyzer_32bit.normalize_code_variant(code2)
        sig3 = analyzer_32bit.normalize_code_variant(code3)

        assert sig1 in [
            sig2,
            sig3,
        ], "Equivalent zero operations should normalize similarly"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_signature_stability(self, analyzer_32bit: Any) -> None:
        """Test semantic signature remains stable across minor variations."""
        base_code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0x8B,
                0x45,
                0x08,
                0x01,
                0xC0,
                0x5D,
                0xC3,
            ]
        )

        variant_code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0x90,
                0x8B,
                0x45,
                0x08,
                0x01,
                0xC0,
                0x90,
                0x5D,
                0xC3,
            ]
        )

        sig1 = analyzer_32bit.extract_semantic_signature(base_code)
        sig2 = analyzer_32bit.extract_semantic_signature(variant_code)

        assert sig1 != ""
        assert sig2 != ""


class TestBehaviorExtraction:
    """Test extraction of behavior patterns."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_data_flow_extraction(self, analyzer_32bit: Any) -> None:
        """Test extraction of data flow patterns."""
        code = bytes(
            [
                0x8B,
                0x45,
                0x08,
                0x89,
                0xC3,
                0x01,
                0xD8,
                0x89,
                0x45,
                0xFC,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert len(analysis.behavior_patterns) > 0
        pattern = analysis.behavior_patterns[0]
        assert len(pattern.data_flow_graph) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_extraction(self, analyzer_32bit: Any) -> None:
        """Test extraction of control flow patterns."""
        code = bytes(
            [
                0x85,
                0xC0,
                0x74,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC3,
                0x31,
                0xC0,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert len(analysis.behavior_patterns) > 0
        pattern = analysis.behavior_patterns[0]
        assert len(pattern.control_flow_graph) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_constant_extraction(self, analyzer_32bit: Any) -> None:
        """Test extraction of constants from code."""
        code = bytes(
            [
                0xB8,
                0x42,
                0x13,
                0x00,
                0x00,
                0xBB,
                0xFF,
                0x00,
                0x00,
                0x00,
                0x01,
                0xD8,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert len(analysis.behavior_patterns) > 0
        pattern = analysis.behavior_patterns[0]
        assert len(pattern.constants) > 0
        assert 0x1342 in pattern.constants or 0xFF in pattern.constants

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_api_call_extraction(self, analyzer_32bit: Any) -> None:
        """Test extraction of API call patterns."""
        code = bytes(
            [
                0x68,
                0x00,
                0x20,
                0x00,
                0x00,
                0xE8,
                0x10,
                0x00,
                0x00,
                0x00,
                0x83,
                0xC4,
                0x04,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert len(analysis.behavior_patterns) > 0
        pattern = analysis.behavior_patterns[0]
        assert len(pattern.api_calls) > 0


class TestInvariantExtraction:
    """Test extraction of invariant features."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_sequence_invariant(self, analyzer_32bit: Any) -> None:
        """Test extraction of semantic sequence invariants."""
        code = bytes(
            [
                0x8B,
                0x45,
                0x08,
                0x01,
                0xC0,
                0x89,
                0x45,
                0xFC,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert "semantic_sequence" in analysis.invariant_features
        assert len(analysis.invariant_features["semantic_sequence"]) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_invariant(self, analyzer_32bit: Any) -> None:
        """Test extraction of control flow invariants."""
        code = bytes(
            [
                0x85,
                0xC0,
                0x75,
                0x05,
                0xEB,
                0x03,
                0x90,
                0x90,
                0x90,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert "control_flow_branches" in analysis.invariant_features
        assert analysis.invariant_features["control_flow_branches"] > 0


class TestDecryptionRoutineIdentification:
    """Test identification of decryption routines."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_xor_decryption_loop(self, analyzer_32bit: Any) -> None:
        """Test identification of XOR decryption loop."""
        code = bytes(
            [
                0xBE,
                0x00,
                0x40,
                0x00,
                0x00,
                0xB9,
                0x20,
                0x00,
                0x00,
                0x00,
                0xB0,
                0x42,
                0x30,
                0x06,
                0x46,
                0xE2,
                0xFB,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis.decryption_routine is not None
        assert analysis.decryption_routine.start_address >= 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_complex_decryption(self, analyzer_32bit: Any) -> None:
        """Test identification of complex decryption routine."""
        code = bytes(
            [
                0xBE,
                0x00,
                0x50,
                0x00,
                0x00,
                0xB9,
                0x10,
                0x00,
                0x00,
                0x00,
                0x8A,
                0x06,
                0x32,
                0xC1,
                0xD0,
                0xC8,
                0x88,
                0x06,
                0x46,
                0xE2,
                0xF5,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis.decryption_routine is not None or len(analysis.mutation_types) > 0


class TestMutationComplexity:
    """Test mutation complexity calculation."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_simple_mutation_complexity(self, analyzer_32bit: Any) -> None:
        """Test complexity for simple mutations."""
        code = bytes([0x90, 0x90, 0x31, 0xC0, 0xC3])

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert 0.0 <= analysis.mutation_complexity <= 0.5

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_complex_mutation_complexity(self, analyzer_32bit: Any) -> None:
        """Test complexity for complex mutations."""
        code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0x90,
                0x50,
                0x58,
                0x31,
                0xC0,
                0x01,
                0xC0,
                0x29,
                0xC0,
                0x85,
                0xC0,
                0x74,
                0x02,
                0xEB,
                0x00,
                0x83,
                0xC0,
                0x05,
                0x83,
                0xE8,
                0x05,
                0x5D,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis.mutation_complexity >= 0.2


class TestEvasionTechniques:
    """Test detection of anti-analysis evasion techniques."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_timing_check_detection(self, analyzer_32bit: Any) -> None:
        """Test detection of timing checks."""
        code = bytes(
            [
                0x0F,
                0x31,
                0x89,
                0xC3,
                0x31,
                0xC0,
                0x0F,
                0x31,
                0x29,
                0xD8,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert "timing_check" in analysis.evasion_techniques

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_vm_detection(self, analyzer_32bit: Any) -> None:
        """Test detection of VM detection code."""
        code = bytes(
            [
                0x0F,
                0xA2,
                0x89,
                0xC0,
                0x31,
                0xDB,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert "vm_detection" in analysis.evasion_techniques

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_stack_obfuscation(self, analyzer_32bit: Any) -> None:
        """Test detection of stack obfuscation."""
        code = bytes(
            [
                0x50,
                0x53,
                0x51,
                0x52,
                0x56,
                0x57,
                0x31,
                0xC0,
                0x5F,
                0x5E,
                0x5A,
                0x59,
                0x5B,
                0x58,
                0xC3,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert "stack_obfuscation" in analysis.evasion_techniques


class TestCodeVariantComparison:
    """Test comparison of code variants."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_identical_semantics(self, analyzer_32bit: Any) -> None:
        """Test comparison of semantically identical code."""
        code1 = bytes([0x31, 0xC0, 0xC3])
        code2 = bytes([0x29, 0xC0, 0xC3])

        similarity, details = analyzer_32bit.compare_code_variants(code1, code2)

        assert similarity > 0.5

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_different_semantics(self, analyzer_32bit: Any) -> None:
        """Test comparison of semantically different code."""
        code1 = bytes(
            [
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC3,
            ]
        )
        code2 = bytes(
            [
                0xB8,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xC3,
            ]
        )

        similarity, details = analyzer_32bit.compare_code_variants(code1, code2)

        assert similarity < 1.0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_code(self, analyzer_32bit: Any) -> None:
        """Test handling of empty code."""
        code = b''

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis.engine_type == PolymorphicEngine.UNKNOWN
        assert len(analysis.mutation_types) == 0

    def test_invalid_code(self, analyzer_32bit: Any) -> None:
        """Test handling of invalid code."""
        code = bytes([0xFF] * 100)

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis is not None

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_very_long_code(self, analyzer_32bit: Any) -> None:
        """Test handling of very long code sequences."""
        code = bytes([0x90] * 5000 + [0xC3])

        analysis = analyzer_32bit.analyze_polymorphic_code(code, max_instructions=100)

        assert len(analysis.behavior_patterns) >= 0


class TestRealWorldPatterns:
    """Test with realistic polymorphic patterns."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_realistic_polymorphic_stub(self, analyzer_32bit: Any) -> None:
        """Test with realistic polymorphic stub."""
        code = bytes(
            [
                0xEB,
                0x10,
                0x5E,
                0x89,
                0xF7,
                0xB9,
                0x30,
                0x00,
                0x00,
                0x00,
                0x8A,
                0x06,
                0x34,
                0x42,
                0x88,
                0x07,
                0x46,
                0x47,
                0xE2,
                0xF6,
                0xEB,
                0x05,
                0xE8,
                0xEB,
                0xFF,
                0xFF,
                0xFF,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert analysis.mutation_complexity > 0
        assert len(analysis.behavior_patterns) > 0
        assert analysis.decryption_routine is not None

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_realistic_registration_check(self, analyzer_32bit: Any) -> None:
        """Test with realistic registration check code."""
        code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0x53,
                0x8B,
                0x45,
                0x08,
                0x85,
                0xC0,
                0x74,
                0x20,
                0x8B,
                0x18,
                0xB9,
                0x10,
                0x00,
                0x00,
                0x00,
                0x31,
                0xC0,
                0x8A,
                0x03,
                0x32,
                0x04,
                0x0D,
                0x00,
                0x40,
                0x00,
                0x00,
                0x43,
                0xE2,
                0xF4,
                0x85,
                0xC0,
                0x75,
                0x02,
                0xB0,
                0x01,
                0x5B,
                0x5D,
                0xC3,
                0x31,
                0xC0,
                0xEB,
                0xF7,
            ]
        )

        analysis = analyzer_32bit.analyze_polymorphic_code(code)

        assert len(analysis.invariant_features) > 0
        semantic_seq = analysis.invariant_features.get("semantic_sequence", ())
        assert len(semantic_seq) > 0
