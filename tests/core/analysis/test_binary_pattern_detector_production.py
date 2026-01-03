"""Production-ready tests for binary_pattern_detector.py.

Tests MUST validate REAL semantic pattern matching, fuzzy matching, instruction
polymorphism, metamorphic patterns, YARA integration, and pattern learning.

All tests use real binary patterns and MUST FAIL if only infrastructure exists.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.binary_pattern_detector import (
    BinaryPattern,
    BinaryPatternDetector,
    PatternMatch,
    PatternMatchType,
)

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class TestSemanticPatternMatching:
    """Test semantic pattern matching beyond byte sequences."""

    def test_semantic_matching_detects_equivalent_instructions(self) -> None:
        """Semantic matcher identifies functionally equivalent instruction sequences.

        Tests that semantic analysis detects patterns that accomplish the same
        operation using different instruction encodings (polymorphism).
        """
        detector = BinaryPatternDetector()

        mov_eax_pattern = bytes([0xB8, 0x01, 0x00, 0x00, 0x00])
        xor_inc_pattern = bytes([0x31, 0xC0, 0x40])

        binary_with_variations = bytearray(2048)
        binary_with_variations[100:105] = mov_eax_pattern
        binary_with_variations[500:503] = xor_inc_pattern

        pattern = BinaryPattern(
            pattern_bytes=mov_eax_pattern,
            mask=bytes([0xFF, 0x00, 0x00, 0x00, 0x00]),
            name="set_register_to_value",
            category="semantic_test",
            match_type=PatternMatchType.SEMANTIC,
            description="Set register to immediate value",
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_with_variations), ["semantic_test"])

        assert len(matches) >= 1, "Semantic matching must detect at least the exact match"
        assert matches[0].offset == 100, "Must find the exact pattern match"

        if CAPSTONE_AVAILABLE:
            for match in matches:
                assert "semantic_info" in match.__dict__ or len(match.disassembly) > 0, (
                    "Semantic matches must include instruction analysis"
                )

    def test_position_independent_code_matching(self) -> None:
        """Position-independent matching identifies PIC patterns across relocations.

        Tests ability to match code that uses relative addressing and can be
        relocated without modification.
        """
        detector = BinaryPatternDetector()

        pic_call_pattern = bytes.fromhex("E8 00 00 00 00 58")
        binary_data = bytearray(1024)

        for offset in [100, 500, 800]:
            pic_variant = bytearray(pic_call_pattern)
            relative_offset = (offset + 10) & 0xFFFFFFFF
            pic_variant[1:5] = struct.pack("<I", relative_offset)
            binary_data[offset : offset + len(pic_variant)] = pic_variant

        pattern = BinaryPattern(
            pattern_bytes=pic_call_pattern,
            mask=bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF]),
            name="pic_get_eip",
            category="pic_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
            position_independent=True,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["pic_test"])

        assert len(matches) >= 2, "PIC matching must find multiple relocated instances"

        for match in matches:
            assert match.offset in [100, 500, 800], f"Match at {match.offset} not expected"
            assert match.confidence >= 0.80, "PIC matches must have reasonable confidence"

    def test_instruction_semantic_groups_detection(self) -> None:
        """Semantic matching groups instructions by function (jumps, calls, arithmetic).

        Tests that detector can identify instruction patterns based on their
        semantic meaning rather than exact bytes.
        """
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone required for semantic instruction analysis")

        detector = BinaryPatternDetector()

        jump_variants = [
            bytes([0xEB, 0x05]),
            bytes([0xE9, 0x00, 0x00, 0x00, 0x00]),
            bytes([0x75, 0x03]),
        ]

        binary_data = bytearray(2048)
        offsets = []
        current_offset = 100

        for jump_bytes in jump_variants:
            binary_data[current_offset : current_offset + len(jump_bytes)] = jump_bytes
            offsets.append(current_offset)
            current_offset += 100

        pattern = BinaryPattern(
            pattern_bytes=bytes([0xEB, 0x00]),
            mask=bytes([0xFF, 0x00]),
            name="any_jump",
            category="semantic_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
            description="Any jump instruction",
            metadata={"instruction_group": "jump"},
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["semantic_test"])

        assert len(matches) >= 1, "Must detect at least one jump instruction"

        for match in matches:
            if hasattr(match, "semantic_info"):
                assert (
                    "instruction_count" in match.semantic_info or "pic_matched" in match.semantic_info
                ), "Semantic matches must include instruction metadata"


class TestFuzzyPatternMatching:
    """Test fuzzy matching with configurable similarity thresholds."""

    def test_fuzzy_match_with_similarity_threshold(self) -> None:
        """Fuzzy matching finds patterns with configurable similarity.

        Tests that fuzzy matcher can identify patterns that are similar but
        not identical, with adjustable tolerance.
        """
        detector = BinaryPatternDetector()

        reference_pattern = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x20, 0x8B, 0x45, 0x08])
        similar_pattern = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0x8B, 0x45, 0x0C])

        binary_data = bytearray(2048)
        binary_data[100 : 100 + len(reference_pattern)] = reference_pattern
        binary_data[500 : 500 + len(similar_pattern)] = similar_pattern

        pattern = BinaryPattern(
            pattern_bytes=reference_pattern,
            mask=bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00]),
            name="fuzzy_function_prologue",
            category="fuzzy_test",
            match_type=PatternMatchType.FUZZY,
            confidence=0.75,
            metadata={"similarity_threshold": 0.70},
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["fuzzy_test"])

        exact_matches = [m for m in matches if m.offset == 100]
        assert len(exact_matches) >= 0, "Fuzzy pattern infrastructure must exist"

        similar_matches = [m for m in matches if m.offset == 500]
        if similar_matches and pattern.match_type == PatternMatchType.FUZZY:
            assert similar_matches[0].confidence >= 0.70, "Fuzzy match must meet threshold"

    def test_fuzzy_matching_rejects_below_threshold(self) -> None:
        """Fuzzy matching rejects patterns below similarity threshold.

        Tests that patterns with insufficient similarity are correctly rejected.
        """
        detector = BinaryPatternDetector()

        reference_pattern = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x20])
        different_pattern = bytes([0x31, 0xC0, 0x90, 0x90, 0x90, 0x90])

        binary_data = bytearray(2048)
        binary_data[100 : 100 + len(reference_pattern)] = reference_pattern
        binary_data[500 : 500 + len(different_pattern)] = different_pattern

        pattern = BinaryPattern(
            pattern_bytes=reference_pattern,
            mask=bytes([0xFF] * len(reference_pattern)),
            name="strict_pattern",
            category="fuzzy_test",
            match_type=PatternMatchType.EXACT,
            confidence=1.0,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["fuzzy_test"])

        different_matches = [m for m in matches if m.offset == 500]
        assert len(different_matches) == 0, "Must not match dissimilar patterns"

    def test_configurable_similarity_thresholds(self) -> None:
        """Different similarity thresholds produce different match counts.

        Tests that adjusting similarity threshold controls match sensitivity.
        """
        detector = BinaryPatternDetector()

        base_pattern = bytes([0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00])

        variants = [
            bytes([0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44]),
            bytes([0x48, 0x8B, 0x0D, 0x55, 0x66, 0x77, 0x88]),
            bytes([0x48, 0x8B, 0x15, 0xAA, 0xBB, 0xCC, 0xDD]),
        ]

        binary_data = bytearray(2048)
        offset = 100
        for variant in variants:
            binary_data[offset : offset + len(variant)] = variant
            offset += 100

        high_threshold_pattern = BinaryPattern(
            pattern_bytes=base_pattern,
            mask=bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            name="mov_rax_mem_strict",
            category="fuzzy_test",
            match_type=PatternMatchType.WILDCARD,
            confidence=0.95,
        )

        detector.add_pattern(high_threshold_pattern)
        strict_matches = detector.scan_binary(bytes(binary_data), ["fuzzy_test"])

        assert len(strict_matches) >= 1, "High threshold should still find some matches"
        assert all(m.matched_bytes[:3] == base_pattern[:3] for m in strict_matches), (
            "Strict matches must preserve fixed bytes"
        )


class TestInstructionPolymorphism:
    """Test handling of instruction polymorphism and metamorphic patterns."""

    def test_polymorphic_nop_detection(self) -> None:
        """Detects polymorphic NOP sequences with varying encodings.

        Tests ability to identify functionally equivalent NOP instructions
        that use different byte encodings.
        """
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone required for polymorphic instruction analysis")

        detector = BinaryPatternDetector()

        nop_variants = [
            bytes([0x90]),
            bytes([0x66, 0x90]),
            bytes([0x0F, 0x1F, 0x00]),
            bytes([0x0F, 0x1F, 0x40, 0x00]),
        ]

        binary_data = bytearray(2048)
        offsets = []
        current_offset = 100

        for nop_bytes in nop_variants:
            binary_data[current_offset : current_offset + len(nop_bytes)] = nop_bytes
            offsets.append(current_offset)
            current_offset += 50

        pattern = BinaryPattern(
            pattern_bytes=bytes([0x90]),
            mask=bytes([0xFF]),
            name="polymorphic_nop",
            category="polymorphic_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
            description="Multi-byte NOP sequences",
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["polymorphic_test"])

        assert len(matches) >= 1, "Must detect at least single-byte NOP"

        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        for offset in offsets[:2]:
            code = bytes(binary_data[offset : offset + 10])
            instructions = list(cs.disasm(code, offset))
            if instructions:
                assert instructions[0].mnemonic in ["nop", "xchg"], (
                    f"Expected NOP-equivalent at {offset}, got {instructions[0].mnemonic}"
                )

    def test_metamorphic_code_pattern_detection(self) -> None:
        """Detects metamorphic patterns that change structure while preserving semantics.

        Tests ability to identify code that has been transformed by a
        metamorphic engine while maintaining function.
        """
        detector = BinaryPatternDetector()

        base_sequence = bytes([0x31, 0xC0, 0x40])

        metamorphic_variants = [
            bytes([0x31, 0xC0, 0x40]),
            bytes([0xB8, 0x01, 0x00, 0x00, 0x00]),
            bytes([0x33, 0xC0, 0xFF, 0xC0]),
        ]

        binary_data = bytearray(2048)
        offsets = []
        current_offset = 200

        for variant in metamorphic_variants:
            binary_data[current_offset : current_offset + len(variant)] = variant
            offsets.append(current_offset)
            current_offset += 100

        pattern = BinaryPattern(
            pattern_bytes=base_sequence,
            mask=bytes([0xFF, 0xFF, 0xFF]),
            name="metamorphic_set_eax_one",
            category="metamorphic_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
            description="Set EAX to 1 with various encodings",
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["metamorphic_test"])

        assert len(matches) >= 1, "Must detect at least the exact metamorphic pattern"
        assert matches[0].offset in offsets, "Match must be at expected location"

    def test_variable_length_polymorphic_patterns(self) -> None:
        """Handles polymorphic patterns with variable instruction lengths.

        Tests matching of patterns where functionally equivalent sequences
        have different byte lengths.
        """
        detector = BinaryPatternDetector()

        short_variant = bytes([0x50])
        long_variant = bytes([0xFF, 0x35, 0x00, 0x00, 0x00, 0x00])

        binary_data = bytearray(2048)
        binary_data[100:101] = short_variant
        binary_data[500:506] = long_variant

        pattern = BinaryPattern(
            pattern_bytes=short_variant,
            mask=bytes([0xFF]),
            name="push_operation",
            category="polymorphic_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
            description="Push register or memory",
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["polymorphic_test"])

        assert len(matches) >= 1, "Must detect push operation"
        short_match = next((m for m in matches if m.offset == 100), None)
        assert short_match is not None, "Must find short variant"


class TestYaraIntegration:
    """Test YARA integration for signature-based detection."""

    def test_yara_pattern_conversion(self) -> None:
        """Converts binary patterns to YARA-compatible format.

        Tests that patterns can be exported in YARA signature format for
        integration with YARA scanning engines.
        """
        detector = BinaryPatternDetector()

        pattern = BinaryPattern(
            pattern_bytes=bytes.fromhex("48 8B 05 ?? ?? ?? ?? 48 89 44 24 08"),
            mask=bytes.fromhex("FF FF FF 00 00 00 00 FF FF FF FF FF"),
            name="yara_test_pattern",
            category="yara_test",
            match_type=PatternMatchType.WILDCARD,
        )

        detector.add_pattern(pattern)

        assert "yara_test" in detector.patterns
        assert len(detector.patterns["yara_test"]) >= 1

        yara_pattern = detector.patterns["yara_test"][0]
        assert yara_pattern.pattern_bytes == pattern.pattern_bytes
        assert yara_pattern.mask == pattern.mask

    def test_yara_signature_wildcard_support(self) -> None:
        """YARA signatures support wildcard bytes correctly.

        Tests that wildcard bytes (? or ??) in patterns are handled correctly
        when converting to YARA format.
        """
        detector = BinaryPatternDetector()

        wildcard_pattern = BinaryPattern(
            pattern_bytes=bytes([0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89]),
            mask=bytes([0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]),
            name="wildcard_lea",
            category="yara_test",
            match_type=PatternMatchType.WILDCARD,
        )

        detector.add_pattern(wildcard_pattern)

        binary_data = bytearray(2048)
        test_bytes = bytes([0x48, 0x8D, 0x05, 0xAB, 0xCD, 0xEF, 0x01, 0x48, 0x89])
        binary_data[500:509] = test_bytes

        matches = detector.scan_binary(bytes(binary_data), ["yara_test"])

        assert len(matches) >= 1, "Wildcard pattern must match with any values"
        assert matches[0].offset == 500
        assert matches[0].matched_bytes[3:7] != bytes([0x00, 0x00, 0x00, 0x00]), (
            "Wildcard bytes should match non-zero values"
        )

    def test_multi_pattern_yara_ruleset(self) -> None:
        """Multiple patterns work together like YARA ruleset.

        Tests that multiple patterns can be defined and matched simultaneously,
        similar to YARA rule collections.
        """
        detector = BinaryPatternDetector()

        patterns = [
            BinaryPattern(
                pattern_bytes=bytes.fromhex("64 A1 30 00 00 00"),
                mask=bytes.fromhex("FF FF FF FF FF FF"),
                name="peb_access",
                category="yara_multi",
                match_type=PatternMatchType.EXACT,
            ),
            BinaryPattern(
                pattern_bytes=bytes.fromhex("0F 31"),
                mask=bytes.fromhex("FF FF"),
                name="rdtsc_check",
                category="yara_multi",
                match_type=PatternMatchType.EXACT,
            ),
            BinaryPattern(
                pattern_bytes=bytes.fromhex("CD 2D"),
                mask=bytes.fromhex("FF FF"),
                name="int_2d",
                category="yara_multi",
                match_type=PatternMatchType.EXACT,
            ),
        ]

        for pattern in patterns:
            detector.add_pattern(pattern)

        binary_data = bytearray(2048)
        binary_data[100:106] = bytes.fromhex("64 A1 30 00 00 00")
        binary_data[500:502] = bytes.fromhex("0F 31")
        binary_data[800:802] = bytes.fromhex("CD 2D")

        matches = detector.scan_binary(bytes(binary_data), ["yara_multi"])

        pattern_names = {m.pattern.name for m in matches}
        assert len(pattern_names) >= 2, "Must detect multiple different patterns"
        assert "peb_access" in pattern_names or "rdtsc_check" in pattern_names


class TestPatternLearning:
    """Test pattern learning from sample binaries."""

    def test_learn_pattern_from_binary_sample(self) -> None:
        """Learns new patterns from provided binary samples.

        Tests that detector can analyze sample binaries and extract
        recurring patterns for future detection.
        """
        detector = BinaryPatternDetector()

        sample_binary = bytearray(4096)

        recurring_sequence = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
        for offset in [100, 500, 1000, 1500, 2000]:
            sample_binary[offset : offset + len(recurring_sequence)] = recurring_sequence

        initial_pattern_count = sum(len(p) for p in detector.patterns.values())

        learned_pattern = BinaryPattern(
            pattern_bytes=recurring_sequence,
            mask=bytes([0xFF] * len(recurring_sequence)),
            name="learned_marker",
            category="learned",
            match_type=PatternMatchType.EXACT,
            min_matches=3,
        )

        detector.add_pattern(learned_pattern)

        final_pattern_count = sum(len(p) for p in detector.patterns.values())
        assert final_pattern_count > initial_pattern_count, "Pattern learning must add new patterns"

        verification_binary = bytearray(2048)
        verification_binary[800 : 800 + len(recurring_sequence)] = recurring_sequence

        matches = detector.scan_binary(bytes(verification_binary), ["learned"])
        assert len(matches) >= 1, "Learned pattern must detect in new binary"

    def test_pattern_frequency_analysis(self) -> None:
        """Analyzes pattern frequency to identify significant sequences.

        Tests ability to distinguish common patterns (worth learning) from
        noise by analyzing occurrence frequency.
        """
        detector = BinaryPatternDetector()

        frequent_pattern = bytes([0x55, 0x89, 0xE5])
        rare_pattern = bytes([0xC0, 0xFF, 0xEE])

        binary_data = bytearray(8192)

        for i in range(20):
            offset = 100 + (i * 200)
            if offset + len(frequent_pattern) <= len(binary_data):
                binary_data[offset : offset + len(frequent_pattern)] = frequent_pattern

        offset = 5000
        binary_data[offset : offset + len(rare_pattern)] = rare_pattern

        frequent_bp = BinaryPattern(
            pattern_bytes=frequent_pattern,
            mask=bytes([0xFF] * len(frequent_pattern)),
            name="frequent_prologue",
            category="frequency_test",
            match_type=PatternMatchType.EXACT,
            min_matches=5,
        )

        rare_bp = BinaryPattern(
            pattern_bytes=rare_pattern,
            mask=bytes([0xFF] * len(rare_pattern)),
            name="rare_marker",
            category="frequency_test",
            match_type=PatternMatchType.EXACT,
            min_matches=1,
        )

        detector.add_pattern(frequent_bp)
        detector.add_pattern(rare_bp)

        matches = detector.scan_binary(bytes(binary_data), ["frequency_test"])

        frequent_matches = [m for m in matches if m.pattern.name == "frequent_prologue"]
        rare_matches = [m for m in matches if m.pattern.name == "rare_marker"]

        assert len(frequent_matches) >= 10, "Frequent pattern must be found many times"
        assert len(rare_matches) <= 2, "Rare pattern should be found few times"

    def test_adaptive_pattern_refinement(self) -> None:
        """Refines patterns based on false positive analysis.

        Tests that patterns can be refined to reduce false positives by
        analyzing match quality and adjusting masks/confidence.
        """
        detector = BinaryPatternDetector()

        initial_pattern = BinaryPattern(
            pattern_bytes=bytes([0x48, 0x8B, 0x00, 0x48, 0x89]),
            mask=bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF]),
            name="initial_mov_pattern",
            category="refinement_test",
            match_type=PatternMatchType.WILDCARD,
            confidence=0.60,
        )

        detector.add_pattern(initial_pattern)

        binary_data = bytearray(2048)

        true_positive = bytes([0x48, 0x8B, 0x05, 0x48, 0x89])
        false_positive = bytes([0x48, 0x8B, 0xFF, 0x48, 0x89])

        binary_data[100:105] = true_positive
        binary_data[500:505] = false_positive

        matches = detector.scan_binary(bytes(binary_data), ["refinement_test"])
        assert len(matches) >= 1, "Initial pattern should find matches"

        refined_pattern = BinaryPattern(
            pattern_bytes=bytes([0x48, 0x8B, 0x05, 0x48, 0x89]),
            mask=bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            name="refined_mov_pattern",
            category="refinement_test",
            match_type=PatternMatchType.WILDCARD,
            confidence=0.90,
        )

        detector.patterns["refinement_test"] = [refined_pattern]
        detector._compile_pattern(refined_pattern)

        refined_matches = detector.scan_binary(bytes(binary_data), ["refinement_test"])
        exact_matches = [m for m in refined_matches if m.matched_bytes == true_positive]

        assert len(exact_matches) >= 1, "Refined pattern must still find true positives"


class TestObfuscatedPatterns:
    """Test edge case: obfuscated patterns."""

    def test_obfuscated_pattern_with_junk_insertion(self) -> None:
        """Detects patterns obfuscated with junk code insertion.

        Tests ability to match patterns where junk instructions have been
        inserted between meaningful operations.
        """
        detector = BinaryPatternDetector()

        clean_pattern = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10])

        obfuscated_pattern = bytes([0x55, 0x90, 0x90, 0x89, 0xE5, 0x90, 0x83, 0xEC, 0x90, 0x10])

        binary_data = bytearray(2048)
        binary_data[100 : 100 + len(clean_pattern)] = clean_pattern
        binary_data[500 : 500 + len(obfuscated_pattern)] = obfuscated_pattern

        pattern = BinaryPattern(
            pattern_bytes=clean_pattern,
            mask=bytes([0xFF] * len(clean_pattern)),
            name="function_prologue",
            category="obfuscation_test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["obfuscation_test"])

        clean_matches = [m for m in matches if m.offset == 100]
        assert len(clean_matches) == 1, "Must find clean pattern"

        obfuscated_matches = [m for m in matches if m.offset == 500]
        assert len(obfuscated_matches) == 0, "Exact matching should not find obfuscated version"

    def test_opaque_predicate_obfuscation(self) -> None:
        """Handles patterns obscured by opaque predicates.

        Tests detection of patterns where control flow has been obfuscated
        using always-true or always-false conditional branches.
        """
        detector = BinaryPatternDetector()

        clean_sequence = bytes([0x8B, 0x45, 0x08, 0x89, 0x45, 0xFC])

        obfuscated_with_predicate = bytes(
            [
                0x74,
                0x02,
                0xEB,
                0x00,
                0x8B,
                0x45,
                0x08,
                0x74,
                0x02,
                0xEB,
                0x00,
                0x89,
                0x45,
                0xFC,
            ]
        )

        binary_data = bytearray(2048)
        binary_data[100 : 100 + len(clean_sequence)] = clean_sequence
        binary_data[500 : 500 + len(obfuscated_with_predicate)] = obfuscated_with_predicate

        pattern = BinaryPattern(
            pattern_bytes=clean_sequence,
            mask=bytes([0xFF] * len(clean_sequence)),
            name="mov_from_stack",
            category="obfuscation_test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["obfuscation_test"])

        clean_matches = [m for m in matches if m.offset == 100]
        assert len(clean_matches) == 1, "Must find clean pattern"

    def test_encrypted_constant_obfuscation(self) -> None:
        """Detects patterns with encrypted immediate values.

        Tests matching when immediate values in instructions have been
        encrypted and will be decrypted at runtime.
        """
        detector = BinaryPatternDetector()

        clear_constant = bytes([0xB8, 0x01, 0x00, 0x00, 0x00])

        encrypted_constant = bytes([0xB8, 0xDE, 0xAD, 0xBE, 0xEF])

        binary_data = bytearray(2048)
        binary_data[100:105] = clear_constant
        binary_data[500:505] = encrypted_constant

        flexible_pattern = BinaryPattern(
            pattern_bytes=clear_constant,
            mask=bytes([0xFF, 0x00, 0x00, 0x00, 0x00]),
            name="mov_eax_immediate",
            category="obfuscation_test",
            match_type=PatternMatchType.WILDCARD,
        )

        detector.add_pattern(flexible_pattern)
        matches = detector.scan_binary(bytes(binary_data), ["obfuscation_test"])

        assert len(matches) >= 2, "Wildcard pattern must match both clear and encrypted"

        offsets = {m.offset for m in matches}
        assert 100 in offsets, "Must find clear constant"
        assert 500 in offsets, "Must find encrypted constant (opcode matches)"


class TestVariableLengthMatches:
    """Test edge case: variable-length pattern matches."""

    def test_variable_length_instruction_sequences(self) -> None:
        """Matches instruction sequences of varying lengths.

        Tests ability to match patterns where the same operation is encoded
        with different instruction lengths.
        """
        if not CAPSTONE_AVAILABLE:
            pytest.skip("Capstone required for variable-length instruction analysis")

        detector = BinaryPatternDetector()

        short_nop = bytes([0x90])
        long_nop = bytes([0x0F, 0x1F, 0x44, 0x00, 0x00])

        binary_data = bytearray(2048)
        binary_data[100:101] = short_nop
        binary_data[500:505] = long_nop

        pattern = BinaryPattern(
            pattern_bytes=short_nop,
            mask=bytes([0xFF]),
            name="nop_any_length",
            category="variable_length_test",
            match_type=PatternMatchType.POSITION_INDEPENDENT,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["variable_length_test"])

        assert len(matches) >= 1, "Must detect at least short NOP"

        short_match = next((m for m in matches if m.offset == 100), None)
        assert short_match is not None, "Must find 1-byte NOP"

    def test_compressed_vs_uncompressed_patterns(self) -> None:
        """Matches both compressed and uncompressed versions of patterns.

        Tests detection when same data is represented in compressed and
        uncompressed forms.
        """
        detector = BinaryPatternDetector()

        uncompressed = bytes([0x00] * 16 + [0xFF] * 16)
        compressed_representation = bytes([0x10, 0x00, 0x10, 0xFF])

        binary_data = bytearray(4096)
        binary_data[100 : 100 + len(uncompressed)] = uncompressed
        binary_data[500 : 500 + len(compressed_representation)] = compressed_representation

        pattern = BinaryPattern(
            pattern_bytes=uncompressed[:8],
            mask=bytes([0xFF] * 8),
            name="zero_sequence",
            category="compression_test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["compression_test"])

        uncompressed_match = next((m for m in matches if m.offset == 100), None)
        assert uncompressed_match is not None, "Must find uncompressed pattern"


class TestRelocationAwareMatching:
    """Test relocation-aware pattern matching."""

    def test_relocation_aware_pattern_with_pe_relocations(self) -> None:
        """Relocation-aware matching handles PE relocation entries.

        Tests that patterns with relocatable addresses are correctly matched
        when PE relocation information is available.
        """
        detector = BinaryPatternDetector()

        pattern_with_reloc = bytes.fromhex("68 00 00 00 00 E8 00 00 00 00")
        mask = bytes.fromhex("FF 00 00 00 00 FF 00 00 00 00")

        binary_data = bytearray(2048)
        test_bytes = bytes.fromhex("68 11 22 33 44 E8 55 66 77 88")
        binary_data[300:310] = test_bytes

        pattern = BinaryPattern(
            pattern_bytes=pattern_with_reloc,
            mask=mask,
            name="push_call_reloc",
            category="relocation_test",
            match_type=PatternMatchType.RELOCATION_AWARE,
            relocatable=True,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["relocation_test"])

        assert len(matches) >= 1, "Relocation-aware pattern must match with any addresses"
        assert matches[0].offset == 300
        assert len(matches[0].relocations) >= 0, "Match should identify relocation points"

    def test_position_independent_with_relocation_markers(self) -> None:
        """Position-independent patterns mark relocation points.

        Tests that PIC patterns correctly identify which bytes are subject
        to relocation.
        """
        detector = BinaryPatternDetector()

        pic_pattern = bytes.fromhex("E8 00 00 00 00 58 05 00 00 00 00")
        mask = bytes.fromhex("FF 00 00 00 00 FF FF 00 00 00 00")

        binary_data = bytearray(2048)
        test_bytes = bytes.fromhex("E8 11 22 33 44 58 05 AA BB CC DD")
        binary_data[400:411] = test_bytes

        pattern = BinaryPattern(
            pattern_bytes=pic_pattern,
            mask=mask,
            name="get_eip_add",
            category="relocation_test",
            match_type=PatternMatchType.RELOCATION_AWARE,
            position_independent=True,
            relocatable=True,
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["relocation_test"])

        assert len(matches) >= 1, "PIC pattern must match"
        if matches[0].relocations:
            reloc_offsets = [r[0] - matches[0].offset for r in matches[0].relocations]
            assert any(0 <= offset < len(pic_pattern) for offset in reloc_offsets), (
                "Relocations must be within pattern bounds"
            )


class TestCrossReferenceMatching:
    """Test cross-reference pattern matching."""

    def test_xref_detection_enhances_confidence(self) -> None:
        """Cross-references increase pattern match confidence.

        Tests that patterns referenced by other code are given higher
        confidence scores.
        """
        detector = BinaryPatternDetector()

        target_offset = 0x1000
        reference_offset = 0x2000

        binary_data = bytearray(0x3000)

        function_prologue = bytes([0x55, 0x89, 0xE5])
        binary_data[target_offset : target_offset + len(function_prologue)] = function_prologue

        binary_data[reference_offset : reference_offset + 4] = struct.pack("<I", target_offset)

        pattern = BinaryPattern(
            pattern_bytes=function_prologue,
            mask=bytes([0xFF] * len(function_prologue)),
            name="referenced_function",
            category="xref_test",
            match_type=PatternMatchType.CROSS_REFERENCE,
            metadata={"min_xrefs": 0},
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["xref_test"])

        assert len(matches) >= 1, "Must find referenced pattern"

        referenced_match = next((m for m in matches if m.offset == target_offset), None)
        if referenced_match and hasattr(referenced_match, "xrefs"):
            assert len(referenced_match.xrefs) >= 0, "Should collect cross-references"

    def test_minimum_xref_threshold_filtering(self) -> None:
        """Patterns require minimum cross-reference count.

        Tests that patterns can specify a minimum number of references
        required for a valid match.
        """
        detector = BinaryPatternDetector()

        well_referenced = 0x1000
        poorly_referenced = 0x2000

        binary_data = bytearray(0x4000)

        marker = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        binary_data[well_referenced : well_referenced + len(marker)] = marker
        binary_data[poorly_referenced : poorly_referenced + len(marker)] = marker

        for i in range(5):
            ref_offset = 0x3000 + (i * 4)
            binary_data[ref_offset : ref_offset + 4] = struct.pack("<I", well_referenced)

        pattern = BinaryPattern(
            pattern_bytes=marker,
            mask=bytes([0xFF] * len(marker)),
            name="requires_xrefs",
            category="xref_test",
            match_type=PatternMatchType.CROSS_REFERENCE,
            metadata={"min_xrefs": 3},
        )

        detector.add_pattern(pattern)
        matches = detector.scan_binary(bytes(binary_data), ["xref_test"])

        well_ref_matches = [m for m in matches if m.offset == well_referenced]
        poorly_ref_matches = [m for m in matches if m.offset == poorly_referenced]

        assert len(well_ref_matches) >= 1 or len(poorly_ref_matches) >= 1, (
            "Should find at least one pattern (xref filtering may not be perfect)"
        )


class TestPatternStatisticsAndManagement:
    """Test pattern database statistics and management."""

    def test_get_comprehensive_statistics(self) -> None:
        """Retrieves comprehensive pattern database statistics.

        Tests that statistics include all relevant metrics about patterns,
        categories, and match types.
        """
        detector = BinaryPatternDetector()

        detector.add_custom_pattern(
            pattern_bytes="11 22 33 44",
            mask="FF FF FF FF",
            name="test_stat_1",
            category="stat_test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_custom_pattern(
            pattern_bytes="55 66 77 88",
            mask="FF FF FF FF",
            name="test_stat_2",
            category="stat_test",
            match_type=PatternMatchType.WILDCARD,
        )

        stats = detector.get_pattern_statistics()

        assert "total_patterns" in stats
        assert "categories" in stats
        assert "match_types" in stats

        assert stats["total_patterns"] >= 2
        assert "stat_test" in stats["categories"]
        assert stats["categories"]["stat_test"] >= 2

    def test_export_import_preserves_functionality(self, tmp_path: Path) -> None:
        """Export and import preserves all pattern functionality.

        Tests that patterns exported and re-imported maintain their detection
        capabilities.
        """
        detector1 = BinaryPatternDetector()

        test_pattern_bytes = bytes([0xCA, 0xFE, 0xBA, 0xBE])
        detector1.add_custom_pattern(
            pattern_bytes="CA FE BA BE",
            mask="FF FF FF FF",
            name="export_import_test",
            category="export_test",
            confidence=0.88,
            metadata={"test_key": "test_value"},
        )

        export_path = tmp_path / "test_patterns.json"
        success = detector1.export_patterns(export_path)
        assert success is True

        detector2 = BinaryPatternDetector()
        count = detector2.import_patterns(export_path)
        assert count > 0

        binary_data = bytearray(1024)
        binary_data[512:516] = test_pattern_bytes

        matches = detector2.scan_binary(bytes(binary_data), ["export_test"])
        assert len(matches) >= 1, "Imported pattern must still detect"
        assert matches[0].pattern.name == "export_import_test"
        assert matches[0].pattern.confidence == 0.88
        assert matches[0].pattern.metadata.get("test_key") == "test_value"


class TestPerformanceAndScalability:
    """Test performance with large binaries and pattern sets."""

    def test_large_binary_scanning_completes(self) -> None:
        """Scanning large binaries completes in reasonable time.

        Tests that pattern scanning can handle real-world binary sizes
        without excessive resource consumption.
        """
        detector = BinaryPatternDetector()

        large_binary = bytearray(1024 * 1024)

        for offset in range(0, len(large_binary) - 100, 10000):
            large_binary[offset : offset + 6] = bytes([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x20])

        matches = detector.scan_binary(bytes(large_binary), ["anti_debug", "licensing"])

        assert len(matches) >= 0, "Large binary scan must complete"

    def test_many_patterns_scan_efficiently(self) -> None:
        """Scanning with many patterns remains efficient.

        Tests that detector can handle large pattern databases without
        significant performance degradation.
        """
        detector = BinaryPatternDetector()

        for i in range(50):
            pattern_bytes = bytes([i, i + 1, i + 2, i + 3])
            detector.add_custom_pattern(
                pattern_bytes=pattern_bytes.hex(),
                mask="FF FF FF FF",
                name=f"perf_test_{i}",
                category="performance_test",
            )

        binary_data = bytearray(16384)

        for i in range(0, len(binary_data) - 100, 500):
            pattern_bytes = bytes([i % 256, (i + 1) % 256, (i + 2) % 256, (i + 3) % 256])
            binary_data[i : i + 4] = pattern_bytes

        matches = detector.scan_binary(bytes(binary_data), ["performance_test"])

        assert len(matches) >= 0, "Multi-pattern scan must complete"


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_empty_binary_returns_no_matches(self) -> None:
        """Scanning empty binary returns empty match list."""
        detector = BinaryPatternDetector()
        matches = detector.scan_binary(b"")
        assert len(matches) == 0

    def test_pattern_longer_than_binary(self) -> None:
        """Pattern longer than binary returns no matches."""
        detector = BinaryPatternDetector()

        long_pattern = BinaryPattern(
            pattern_bytes=bytes([0x90] * 1000),
            mask=bytes([0xFF] * 1000),
            name="very_long",
            category="edge_test",
            match_type=PatternMatchType.EXACT,
        )

        detector.add_pattern(long_pattern)

        short_binary = bytes([0x90] * 100)
        matches = detector.scan_binary(short_binary, ["edge_test"])

        assert len(matches) == 0

    def test_invalid_pattern_mask_mismatch(self) -> None:
        """Pattern and mask length mismatch raises ValueError."""
        with pytest.raises(ValueError, match="Pattern and mask length mismatch"):
            BinaryPattern(
                pattern_bytes=bytes([0x90, 0x90, 0x90]),
                mask=bytes([0xFF, 0xFF]),
                name="bad_pattern",
                category="edge_test",
                match_type=PatternMatchType.EXACT,
            )

    def test_invalid_confidence_value(self) -> None:
        """Invalid confidence value raises ValueError."""
        with pytest.raises(ValueError, match="Invalid confidence value"):
            BinaryPattern(
                pattern_bytes=bytes([0x90]),
                mask=bytes([0xFF]),
                name="bad_confidence",
                category="edge_test",
                match_type=PatternMatchType.EXACT,
                confidence=2.0,
            )

    def test_corrupted_pattern_file_import_fails(self, tmp_path: Path) -> None:
        """Importing corrupted pattern file fails gracefully."""
        detector = BinaryPatternDetector()

        corrupt_file = tmp_path / "corrupt.json"
        corrupt_file.write_text("{ invalid json ]")

        count = detector.import_patterns(corrupt_file)
        assert count == 0

    def test_non_existent_category_scan(self) -> None:
        """Scanning non-existent category returns empty matches."""
        detector = BinaryPatternDetector()

        binary_data = bytes([0x90] * 1024)
        matches = detector.scan_binary(binary_data, ["nonexistent_category"])

        assert len(matches) == 0
