"""Production-ready tests for Themida CISC VM handler analysis.

Tests validate complete CISC handler detection (0x00-0xFF range), handler semantic
lifting, VM dispatcher tracing, and devirtualization accuracy on real Themida-protected
binaries. All tests MUST FAIL if functionality is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
"""

import logging
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.themida_analyzer import (
    ThemidaAnalyzer,
    ThemidaVersion,
    VMArchitecture,
    VMHandler,
)


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent / "resources" / "protected_binaries" / "themida"
THEMIDA_2X_BINARY = PROTECTED_BINARIES_DIR / "themida_2x_cisc_sample.exe"
THEMIDA_3X_BINARY = PROTECTED_BINARIES_DIR / "themida_3x_cisc_sample.exe"
THEMIDA_31_BINARY = PROTECTED_BINARIES_DIR / "themida_31_cisc_sample.exe"
THEMIDA_MULTILAYER_BINARY = PROTECTED_BINARIES_DIR / "themida_multilayer_sample.exe"
THEMIDA_ENCRYPTED_HANDLERS = PROTECTED_BINARIES_DIR / "themida_encrypted_handlers.exe"


@pytest.fixture
def analyzer() -> ThemidaAnalyzer:
    """Create Themida analyzer instance.

    Returns:
        Configured ThemidaAnalyzer instance for testing.
    """
    return ThemidaAnalyzer()


@pytest.fixture
def themida_2x_sample() -> Path:
    """Provide Themida 2.x CISC protected binary.

    Returns:
        Path to Themida 2.x protected sample binary.
    """
    if not THEMIDA_2X_BINARY.exists():
        pytest.skip(
            f"CRITICAL: Themida 2.x protected binary not found.\n"
            f"Required file: {THEMIDA_2X_BINARY.absolute()}\n"
            f"Place a Themida 2.x protected binary (with CISC virtualization) at:\n"
            f"  {PROTECTED_BINARIES_DIR.absolute()}/\n"
            f"Expected filename: themida_2x_cisc_sample.exe\n"
            f"Binary requirements:\n"
            f"  - Protected with Themida 2.x\n"
            f"  - CISC VM architecture enabled\n"
            f"  - Virtualized functions present\n"
            f"  - Unencrypted or standard encryption\n"
            f"Create test directory structure: {PROTECTED_BINARIES_DIR.absolute()}"
        )
    return THEMIDA_2X_BINARY


@pytest.fixture
def themida_3x_sample() -> Path:
    """Provide Themida 3.x CISC protected binary.

    Returns:
        Path to Themida 3.x protected sample binary.
    """
    if not THEMIDA_3X_BINARY.exists():
        pytest.skip(
            f"CRITICAL: Themida 3.x protected binary not found.\n"
            f"Required file: {THEMIDA_3X_BINARY.absolute()}\n"
            f"Place a Themida 3.x protected binary (with CISC virtualization) at:\n"
            f"  {PROTECTED_BINARIES_DIR.absolute()}/\n"
            f"Expected filename: themida_3x_cisc_sample.exe\n"
            f"Binary requirements:\n"
            f"  - Protected with Themida 3.x (not 3.1+)\n"
            f"  - CISC VM architecture enabled\n"
            f"  - Multiple virtualized functions\n"
            f"  - Standard handler table layout\n"
            f"Create test directory structure: {PROTECTED_BINARIES_DIR.absolute()}"
        )
    return THEMIDA_3X_BINARY


@pytest.fixture
def themida_31_sample() -> Path:
    """Provide Themida 3.1+ CISC protected binary.

    Returns:
        Path to Themida 3.1 protected sample binary.
    """
    if not THEMIDA_31_BINARY.exists():
        pytest.skip(
            f"CRITICAL: Themida 3.1 protected binary not found.\n"
            f"Required file: {THEMIDA_31_BINARY.absolute()}\n"
            f"Place a Themida 3.1+ protected binary (with CISC virtualization) at:\n"
            f"  {PROTECTED_BINARIES_DIR.absolute()}/\n"
            f"Expected filename: themida_31_cisc_sample.exe\n"
            f"Binary requirements:\n"
            f"  - Protected with Themida 3.1 or newer\n"
            f"  - CISC VM architecture enabled\n"
            f"  - Enhanced obfuscation features enabled\n"
            f"  - Anti-analysis countermeasures active\n"
            f"Create test directory structure: {PROTECTED_BINARIES_DIR.absolute()}"
        )
    return THEMIDA_31_BINARY


@pytest.fixture
def multilayer_sample() -> Path:
    """Provide multi-layer virtualized Themida binary.

    Returns:
        Path to multi-layer protected binary.
    """
    if not THEMIDA_MULTILAYER_BINARY.exists():
        pytest.skip(
            f"CRITICAL: Multi-layer Themida binary not found.\n"
            f"Required file: {THEMIDA_MULTILAYER_BINARY.absolute()}\n"
            f"Place a multi-layer Themida protected binary at:\n"
            f"  {PROTECTED_BINARIES_DIR.absolute()}/\n"
            f"Expected filename: themida_multilayer_sample.exe\n"
            f"Binary requirements:\n"
            f"  - Protected with Themida (any 2.x/3.x version)\n"
            f"  - Multiple layers of virtualization\n"
            f"  - Nested VM contexts\n"
            f"  - Complex handler interdependencies\n"
            f"Create test directory structure: {PROTECTED_BINARIES_DIR.absolute()}"
        )
    return THEMIDA_MULTILAYER_BINARY


@pytest.fixture
def encrypted_handlers_sample() -> Path:
    """Provide Themida binary with encrypted handlers.

    Returns:
        Path to encrypted handlers binary.
    """
    if not THEMIDA_ENCRYPTED_HANDLERS.exists():
        pytest.skip(
            f"CRITICAL: Encrypted handlers Themida binary not found.\n"
            f"Required file: {THEMIDA_ENCRYPTED_HANDLERS.absolute()}\n"
            f"Place a Themida protected binary with encrypted handlers at:\n"
            f"  {PROTECTED_BINARIES_DIR.absolute()}/\n"
            f"Expected filename: themida_encrypted_handlers.exe\n"
            f"Binary requirements:\n"
            f"  - Protected with Themida 3.x\n"
            f"  - Handler encryption enabled\n"
            f"  - CISC architecture\n"
            f"  - Requires runtime decryption of VM handlers\n"
            f"Create test directory structure: {PROTECTED_BINARIES_DIR.absolute()}"
        )
    return THEMIDA_ENCRYPTED_HANDLERS


class TestThemidaCISCHandlerDetection:
    """Test complete CISC VM handler detection and extraction."""

    def test_detects_all_cisc_handlers_0x00_to_0xff_range(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must detect ALL Themida CISC VM handlers in 0x00-0xFF range.

        Tests that analyzer identifies complete handler set (256 handlers) in real
        Themida-protected binary. MUST FAIL if only 0x00-0x0C handlers detected.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert result.is_protected, "Failed to detect Themida protection"
        assert result.vm_architecture == VMArchitecture.CISC, (
            f"Expected CISC architecture, got {result.vm_architecture.value}"
        )

        detected_handler_opcodes = set(result.handlers.keys())

        expected_critical_handlers = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        }

        assert expected_critical_handlers.issubset(detected_handler_opcodes), (
            f"Missing critical handlers. Expected at least {expected_critical_handlers}, "
            f"found {detected_handler_opcodes}. Missing: "
            f"{expected_critical_handlers - detected_handler_opcodes}"
        )

        handler_count = len(result.handlers)
        assert handler_count >= 128, (
            f"Incomplete handler detection. Expected >= 128 handlers (full 0x00-0xFF range), "
            f"only detected {handler_count}. This indicates detection limited to 0x00-0x0C range."
        )

        min_expected_handlers = 200
        assert handler_count >= min_expected_handlers, (
            f"Low handler count suggests incomplete implementation. "
            f"Expected >= {min_expected_handlers} handlers for production Themida analysis, "
            f"only detected {handler_count}"
        )

    def test_extracts_handler_metadata_correctly(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Extracted handlers must contain complete metadata (address, size, category, complexity).

        Validates that each detected handler includes all required fields with realistic
        values extracted from binary analysis.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert len(result.handlers) > 0, "No handlers extracted"

        for opcode, handler in result.handlers.items():
            assert isinstance(handler, VMHandler), f"Handler {opcode:02x} has wrong type"

            assert handler.opcode == opcode, (
                f"Handler opcode mismatch: expected {opcode:02x}, got {handler.opcode:02x}"
            )

            assert handler.address > 0, (
                f"Handler {opcode:02x} has invalid address: {handler.address}"
            )

            assert handler.size > 0, (
                f"Handler {opcode:02x} has invalid size: {handler.size}"
            )
            assert handler.size <= 1024, (
                f"Handler {opcode:02x} has unrealistic size: {handler.size} bytes"
            )

            assert len(handler.instructions) > 0, (
                f"Handler {opcode:02x} has no disassembled instructions"
            )

            valid_categories = {
                "arithmetic", "logical", "data_transfer", "comparison",
                "control_flow", "stack_operation", "anti_debug", "complex", "unknown"
            }
            assert handler.category in valid_categories, (
                f"Handler {opcode:02x} has invalid category: {handler.category}"
            )

            assert 1 <= handler.complexity <= 10, (
                f"Handler {opcode:02x} complexity out of range [1-10]: {handler.complexity}"
            )

            assert isinstance(handler.references, list), (
                f"Handler {opcode:02x} references is not a list"
            )

    def test_identifies_handler_table_address(
        self, analyzer: ThemidaAnalyzer, themida_3x_sample: Path
    ) -> None:
        """Analyzer must trace VM dispatcher and identify handler table address.

        Tests that analyzer locates dispatcher jump table in real Themida binary,
        critical for complete handler extraction.
        """
        result = analyzer.analyze(str(themida_3x_sample))

        assert result.is_protected, "Failed to detect Themida protection"

        assert result.handler_table_address != 0, (
            "Failed to locate VM handler dispatch table. "
            "This is critical for handler extraction."
        )

        assert result.handler_table_address > 0x1000, (
            f"Handler table address {result.handler_table_address:08x} appears invalid "
            "(too low, likely uninitialized)"
        )

        with open(themida_3x_sample, "rb") as f:
            binary_data = f.read()

        assert result.handler_table_address < len(binary_data), (
            f"Handler table address {result.handler_table_address:08x} exceeds binary size "
            f"{len(binary_data):08x}"
        )

    def test_detects_themida_version_specific_handlers(
        self, analyzer: ThemidaAnalyzer, themida_31_sample: Path
    ) -> None:
        """Analyzer must correctly identify Themida 3.1 version-specific handler variations.

        Tests version detection and version-specific handler patterns unique to Themida 3.1.
        """
        result = analyzer.analyze(str(themida_31_sample))

        assert result.is_protected, "Failed to detect Themida protection"
        assert result.version in [ThemidaVersion.THEMIDA_3X, ThemidaVersion.WINLICENSE_3X], (
            f"Expected Themida 3.x version, got {result.version.value}"
        )

        assert len(result.handlers) > 0, "No handlers detected in Themida 3.1 binary"

        advanced_opcodes = {
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
            0xB0, 0xB5, 0xBA, 0xBF,
            0xC0, 0xC5, 0xCA, 0xCF,
        }

        detected_advanced = advanced_opcodes & set(result.handlers.keys())
        assert len(detected_advanced) > 0, (
            f"No Themida 3.x advanced handlers detected. "
            f"Expected some of {advanced_opcodes}, found none."
        )


class TestThemidaCISCHandlerSemantics:
    """Test CISC handler semantic lifting and instruction translation."""

    def test_lifts_arithmetic_handler_semantics(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must implement semantic lifting for arithmetic CISC handlers.

        Tests that arithmetic operations (ADD, SUB, MUL, DIV) are correctly lifted
        to native instruction semantics.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        arithmetic_opcodes = {0x01, 0x02, 0x03, 0x19, 0x1A, 0x1B, 0x1C}
        detected_arithmetic = arithmetic_opcodes & set(result.handlers.keys())

        assert len(detected_arithmetic) >= 4, (
            f"Insufficient arithmetic handlers detected. "
            f"Expected >= 4 from {arithmetic_opcodes}, found {len(detected_arithmetic)}"
        )

        for opcode in detected_arithmetic:
            handler = result.handlers[opcode]

            assert handler.category == "arithmetic", (
                f"Handler {opcode:02x} not categorized as arithmetic: {handler.category}"
            )

            mnemonics = [insn[1] for insn in handler.instructions]
            arithmetic_insns = {"add", "sub", "mul", "imul", "div", "idiv"}
            has_arithmetic = bool(arithmetic_insns & set(mnemonics))

            assert has_arithmetic, (
                f"Arithmetic handler {opcode:02x} contains no arithmetic instructions: {mnemonics}"
            )

    def test_lifts_control_flow_handler_semantics(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must implement semantic lifting for control flow CISC handlers.

        Tests that control flow operations (JMP, JZ, JNZ, CALL, RET) are correctly
        identified and lifted.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        control_flow_opcodes = {
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x2A, 0x2B, 0x2C,
            0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
        }
        detected_cf = control_flow_opcodes & set(result.handlers.keys())

        assert len(detected_cf) >= 6, (
            f"Insufficient control flow handlers detected. "
            f"Expected >= 6 from {control_flow_opcodes}, found {len(detected_cf)}"
        )

        for opcode in detected_cf:
            handler = result.handlers[opcode]

            assert handler.category == "control_flow", (
                f"Handler {opcode:02x} not categorized as control_flow: {handler.category}"
            )

            mnemonics = [insn[1] for insn in handler.instructions]
            cf_insns = {"jmp", "je", "jne", "jz", "jnz", "jg", "jl", "ja", "jb", "call", "ret"}
            has_cf = bool(cf_insns & set(mnemonics))

            assert has_cf, (
                f"Control flow handler {opcode:02x} contains no CF instructions: {mnemonics}"
            )

    def test_lifts_memory_access_handler_semantics(
        self, analyzer: ThemidaAnalyzer, themida_3x_sample: Path
    ) -> None:
        """Analyzer must implement semantic lifting for memory access CISC handlers.

        Tests that memory operations (MOV [mem], LOAD, STORE) are correctly lifted.
        """
        result = analyzer.analyze(str(themida_3x_sample))

        memory_opcodes = {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        }
        detected_memory = memory_opcodes & set(result.handlers.keys())

        assert len(detected_memory) >= 5, (
            f"Insufficient memory access handlers detected. "
            f"Expected >= 5 from {memory_opcodes}, found {len(detected_memory)}"
        )

        for opcode in detected_memory:
            handler = result.handlers[opcode]

            assert handler.category in ["data_transfer", "complex"], (
                f"Handler {opcode:02x} not categorized as data_transfer/complex: {handler.category}"
            )

            mnemonics = [insn[1] for insn in handler.instructions]
            memory_insns = {"mov", "movzx", "movsx", "lea"}
            has_memory = bool(memory_insns & set(mnemonics))

            assert has_memory, (
                f"Memory handler {opcode:02x} contains no memory instructions: {mnemonics}"
            )


class TestThemidaRISCFISHHandlers:
    """Test RISC and FISH VM handler semantic lifting."""

    def test_implements_risc_handler_patterns(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must implement RISC VM handler pattern matching.

        While sample is CISC, analyzer must have RISC patterns defined for complete
        Themida analysis capability.
        """
        assert hasattr(analyzer, "RISC_HANDLER_PATTERNS"), (
            "Analyzer missing RISC_HANDLER_PATTERNS attribute"
        )

        risc_patterns = analyzer.RISC_HANDLER_PATTERNS
        assert isinstance(risc_patterns, dict), "RISC_HANDLER_PATTERNS must be dict"

        expected_risc_opcodes = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        }

        assert expected_risc_opcodes.issubset(risc_patterns.keys()), (
            f"RISC patterns incomplete. Expected {expected_risc_opcodes}, "
            f"found {set(risc_patterns.keys()) & expected_risc_opcodes}"
        )

        for opcode, pattern in risc_patterns.items():
            assert isinstance(pattern, bytes), (
                f"RISC pattern {opcode:02x} is not bytes: {type(pattern)}"
            )
            assert len(pattern) >= 2, (
                f"RISC pattern {opcode:02x} too short: {len(pattern)} bytes"
            )

    def test_implements_fish_handler_patterns(
        self, analyzer: ThemidaAnalyzer, themida_3x_sample: Path
    ) -> None:
        """Analyzer must implement FISH VM handler pattern matching.

        FISH (x64 hybrid) handlers required for Themida 3.x x64 binaries.
        """
        assert hasattr(analyzer, "FISH_HANDLER_PATTERNS"), (
            "Analyzer missing FISH_HANDLER_PATTERNS attribute"
        )

        fish_patterns = analyzer.FISH_HANDLER_PATTERNS
        assert isinstance(fish_patterns, dict), "FISH_HANDLER_PATTERNS must be dict"

        expected_fish_opcodes = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
            0xA0, 0xA1, 0xA2, 0xA3,
        }

        assert expected_fish_opcodes.issubset(fish_patterns.keys()), (
            f"FISH patterns incomplete. Expected {expected_fish_opcodes}, "
            f"found {set(fish_patterns.keys()) & expected_fish_opcodes}"
        )

        for opcode, pattern in fish_patterns.items():
            assert isinstance(pattern, bytes), (
                f"FISH pattern {opcode:02x} is not bytes: {type(pattern)}"
            )

            has_x64_prefix = pattern.startswith((b"\x48", b"\x4c", b"\x41", b"\x49"))
            has_x64_insn = b"\x48" in pattern or b"\x4c" in pattern

            assert has_x64_prefix or has_x64_insn or len(pattern) <= 2, (
                f"FISH pattern {opcode:02x} lacks x64 REX prefix: {pattern.hex()}"
            )


class TestThemidaVMContextExtraction:
    """Test VM context extraction and register mapping."""

    def test_extracts_vm_entry_points(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must trace VM entry points in real Themida binary.

        VM entry points are critical for devirtualization - must detect all entries.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert len(result.vm_entry_points) > 0, (
            "No VM entry points detected. This is critical failure - "
            "cannot devirtualize without entry points."
        )

        assert len(result.vm_entry_points) >= 1, (
            "Expected at least 1 VM entry point in protected binary"
        )

        for entry_point in result.vm_entry_points:
            assert entry_point > 0, f"Invalid entry point: {entry_point}"
            assert entry_point < 0x10000000, (
                f"Entry point {entry_point:08x} exceeds reasonable range"
            )

    def test_extracts_vm_contexts_with_register_mapping(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must extract VM context structures with register mappings.

        VM context contains critical metadata for semantic lifting and devirtualization.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert len(result.vm_contexts) > 0, (
            "No VM contexts extracted. Cannot perform devirtualization without contexts."
        )

        for context in result.vm_contexts:
            assert context.vm_entry > 0, "VM entry point not set in context"

            assert context.context_size > 0, (
                f"Invalid context size: {context.context_size}"
            )
            assert context.context_size <= 0x10000, (
                f"Context size {context.context_size:08x} unrealistically large"
            )

            assert len(context.register_mapping) > 0, (
                "VM context missing register mapping - required for semantic lifting"
            )

            expected_registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
            mapped_registers = set(context.register_mapping.keys())

            common_registers = expected_registers & mapped_registers
            assert len(common_registers) >= 4, (
                f"Insufficient register mapping. Expected {expected_registers}, "
                f"found {mapped_registers}"
            )

            assert context.stack_offset >= 0, (
                f"Invalid stack offset: {context.stack_offset}"
            )
            assert context.flags_offset >= 0, (
                f"Invalid flags offset: {context.flags_offset}"
            )

    def test_identifies_vm_exit_points(
        self, analyzer: ThemidaAnalyzer, themida_3x_sample: Path
    ) -> None:
        """Analyzer must identify VM exit points for complete devirtualization.

        Exit points define boundaries of virtualized code regions.
        """
        result = analyzer.analyze(str(themida_3x_sample))

        contexts_with_exit = [c for c in result.vm_contexts if c.vm_exit > 0]

        assert len(contexts_with_exit) > 0, (
            "No VM contexts have exit points identified. "
            "This prevents accurate devirtualization boundary detection."
        )

        for context in contexts_with_exit:
            assert context.vm_exit > context.vm_entry, (
                f"VM exit {context.vm_exit:08x} before entry {context.vm_entry:08x}"
            )

            vm_code_size = context.vm_exit - context.vm_entry
            assert vm_code_size < 100000, (
                f"VM region size {vm_code_size} unrealistically large"
            )


class TestThemidaDevirtualization:
    """Test devirtualization and native code extraction."""

    def test_devirtualizes_code_with_90_percent_accuracy(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must extract original code from virtualized functions with >90% accuracy.

        This is the critical test validating production-ready devirtualization capability.
        MUST FAIL if devirtualization confidence < 90%.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert len(result.devirtualized_sections) > 0, (
            "No devirtualized code sections produced. "
            "This is critical failure - primary purpose of analyzer."
        )

        high_confidence_sections = [
            section for section in result.devirtualized_sections
            if section.confidence >= 90.0
        ]

        assert len(high_confidence_sections) > 0, (
            f"No devirtualized sections with >= 90% confidence. "
            f"Best confidence: {max((s.confidence for s in result.devirtualized_sections), default=0.0):.1f}%. "
            f"This indicates incomplete handler implementation or broken semantic lifting."
        )

        total_confidence = sum(s.confidence for s in result.devirtualized_sections)
        avg_confidence = total_confidence / len(result.devirtualized_sections)

        assert avg_confidence >= 90.0, (
            f"Average devirtualization confidence {avg_confidence:.1f}% below 90% threshold. "
            f"This indicates incomplete CISC handler coverage (likely only 0x00-0x0C implemented)."
        )

    def test_produces_valid_native_code_output(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Devirtualized output must contain valid native x86/x64 code.

        Tests that devirtualization produces actual executable code, not placeholders.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert len(result.devirtualized_sections) > 0, "No devirtualized sections"

        for section in result.devirtualized_sections:
            assert len(section.native_code) > 0, (
                f"Devirtualized section at {section.original_rva:08x} has empty native code"
            )

            assert len(section.assembly) > 0, (
                f"Devirtualized section at {section.original_rva:08x} has no assembly output"
            )

            assert len(section.vm_handlers_used) > 0, (
                f"Devirtualized section at {section.original_rva:08x} reports no handlers used"
            )

            placeholder_count = sum(
                1 for line in section.assembly
                if "vm_handler_" in line or line.startswith("db ")
            )
            total_lines = len(section.assembly)

            placeholder_ratio = placeholder_count / total_lines if total_lines > 0 else 1.0

            assert placeholder_ratio < 0.5, (
                f"Devirtualized section at {section.original_rva:08x} has {placeholder_ratio:.1%} "
                f"placeholder instructions - indicates incomplete handler implementation"
            )

    def test_tracks_handler_usage_during_devirtualization(
        self, analyzer: ThemidaAnalyzer, themida_3x_sample: Path
    ) -> None:
        """Devirtualization must track which VM handlers were used.

        Handler usage tracking critical for validating coverage and detecting gaps.
        """
        result = analyzer.analyze(str(themida_3x_sample))

        assert len(result.devirtualized_sections) > 0, "No devirtualized sections"

        all_used_handlers: set[int] = set()
        for section in result.devirtualized_sections:
            all_used_handlers.update(section.vm_handlers_used)

        assert len(all_used_handlers) >= 10, (
            f"Only {len(all_used_handlers)} unique handlers used during devirtualization. "
            f"Expected >= 10 for realistic virtualized code. "
            f"This suggests incomplete handler implementation."
        )

        for section in result.devirtualized_sections:
            unique_handlers = len(set(section.vm_handlers_used))
            total_handlers = len(section.vm_handlers_used)

            assert unique_handlers > 0, (
                f"Section at {section.original_rva:08x} reports 0 unique handlers"
            )

            handler_diversity = unique_handlers / total_handlers if total_handlers > 0 else 0
            assert handler_diversity > 0.1, (
                f"Section at {section.original_rva:08x} has low handler diversity "
                f"({handler_diversity:.1%}) - may indicate incomplete analysis"
            )


class TestThemidaAntiAnalysisTechniques:
    """Test handling of Themida anti-analysis techniques."""

    def test_handles_junk_code_insertion(
        self, analyzer: ThemidaAnalyzer, themida_31_sample: Path
    ) -> None:
        """Analyzer must handle Themida junk code and opaque predicates.

        Themida inserts significant junk code - analyzer must distinguish real handlers.
        """
        result = analyzer.analyze(str(themida_31_sample))

        assert result.is_protected, "Failed to detect Themida protection"

        assert len(result.handlers) > 50, (
            f"Only {len(result.handlers)} handlers detected in Themida 3.1 binary. "
            f"Junk code may be preventing handler detection."
        )

        for handler in result.handlers.values():
            assert handler.complexity <= 10, (
                f"Handler {handler.opcode:02x} complexity {handler.complexity} exceeds maximum. "
                f"May include junk code in analysis."
            )

    def test_detects_anti_debug_handlers(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analyzer must identify anti-debugging VM handlers.

        Themida embeds anti-debug checks in VM handlers - must detect them.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        anti_debug_handlers = [
            handler for handler in result.handlers.values()
            if handler.category == "anti_debug"
        ]

        assert len(anti_debug_handlers) > 0, (
            "No anti-debug handlers detected. Themida always includes anti-debug - "
            "detection logic may be broken."
        )

        assert len(result.anti_debug_locations) > 0, (
            "No anti-debug locations identified. Expected multiple anti-debug checks "
            "in Themida-protected binary."
        )

    def test_detects_control_flow_obfuscation(
        self, analyzer: ThemidaAnalyzer, themida_31_sample: Path
    ) -> None:
        """Analyzer must handle Themida control flow obfuscation.

        Themida heavily obfuscates control flow - handler extraction must still succeed.
        """
        result = analyzer.analyze(str(themida_31_sample))

        control_flow_handlers = [
            handler for handler in result.handlers.values()
            if handler.category == "control_flow"
        ]

        assert len(control_flow_handlers) >= 5, (
            f"Only {len(control_flow_handlers)} control flow handlers detected. "
            f"Expected >= 5 despite obfuscation."
        )

        complex_handlers = [
            handler for handler in result.handlers.values()
            if handler.complexity >= 7
        ]

        assert len(complex_handlers) > 0, (
            "No complex handlers detected. Themida 3.1 obfuscation should produce "
            "handlers with high complexity scores."
        )


class TestThemidaEdgeCases:
    """Test edge cases and version-specific variations."""

    def test_handles_multi_layer_virtualization(
        self, analyzer: ThemidaAnalyzer, multilayer_sample: Path
    ) -> None:
        """Analyzer must handle multi-layer nested virtualization.

        Some Themida binaries have multiple virtualization layers - must detect all.
        """
        result = analyzer.analyze(str(multilayer_sample))

        assert result.is_protected, "Failed to detect Themida protection"

        assert len(result.vm_entry_points) >= 2, (
            f"Expected >= 2 VM entry points for multi-layer binary, found {len(result.vm_entry_points)}"
        )

        assert len(result.vm_contexts) >= 2, (
            f"Expected >= 2 VM contexts for multi-layer binary, found {len(result.vm_contexts)}"
        )

    def test_handles_encrypted_handlers(
        self, analyzer: ThemidaAnalyzer, encrypted_handlers_sample: Path
    ) -> None:
        """Analyzer must detect encrypted handler patterns.

        Themida 3.x can encrypt VM handlers - analyzer must identify this condition.
        """
        result = analyzer.analyze(str(encrypted_handlers_sample))

        assert result.is_protected, "Failed to detect Themida protection"

        if len(result.handlers) < 50:
            assert len(result.encryption_keys) > 0, (
                "Low handler count and no encryption keys detected. "
                "Binary may have encrypted handlers that weren't identified."
            )

    def test_detects_version_specific_variations(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path, themida_31_sample: Path
    ) -> None:
        """Analyzer must differentiate between Themida 2.x and 3.1 handler variations.

        Handler implementations changed between versions - detection must be accurate.
        """
        result_2x = analyzer.analyze(str(themida_2x_sample))
        result_31 = analyzer.analyze(str(themida_31_sample))

        assert result_2x.version == ThemidaVersion.THEMIDA_2X, (
            f"Incorrect version detection for 2.x sample: {result_2x.version.value}"
        )

        assert result_31.version in [ThemidaVersion.THEMIDA_3X, ThemidaVersion.WINLICENSE_3X], (
            f"Incorrect version detection for 3.1 sample: {result_31.version.value}"
        )

        handlers_2x = set(result_2x.handlers.keys())
        handlers_31 = set(result_31.handlers.keys())

        assert handlers_2x != handlers_31, (
            "Handler sets identical between Themida 2.x and 3.1 - "
            "version-specific detection not working"
        )


class TestThemidaIntegration:
    """Test complete end-to-end Themida analysis workflow."""

    def test_complete_analysis_workflow(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Test complete analysis workflow from detection to devirtualization.

        Validates entire pipeline: detection -> handler extraction -> context extraction
        -> semantic lifting -> devirtualization.
        """
        result = analyzer.analyze(str(themida_2x_sample))

        assert result.is_protected, "Step 1 failed: Protection detection"
        assert result.vm_architecture != VMArchitecture.UNKNOWN, (
            "Step 2 failed: VM architecture detection"
        )
        assert len(result.vm_sections) > 0, "Step 3 failed: VM section identification"
        assert len(result.vm_entry_points) > 0, "Step 4 failed: Entry point discovery"
        assert result.handler_table_address != 0, "Step 5 failed: Handler table location"
        assert len(result.handlers) >= 50, "Step 6 failed: Handler extraction"
        assert len(result.vm_contexts) > 0, "Step 7 failed: VM context extraction"
        assert len(result.devirtualized_sections) > 0, "Step 8 failed: Devirtualization"

        avg_confidence = sum(s.confidence for s in result.devirtualized_sections) / len(result.devirtualized_sections)
        assert avg_confidence >= 90.0, (
            f"Step 9 failed: Devirtualization quality check ({avg_confidence:.1f}% < 90%)"
        )

        assert result.confidence >= 80.0, (
            f"Overall analysis confidence {result.confidence:.1f}% below 80% threshold"
        )

    def test_analysis_performance(
        self, analyzer: ThemidaAnalyzer, themida_2x_sample: Path
    ) -> None:
        """Analysis must complete within reasonable time for production use.

        Large binaries must be analyzable within practical timeframes.
        """
        import time

        start_time = time.time()
        result = analyzer.analyze(str(themida_2x_sample))
        elapsed_time = time.time() - start_time

        assert elapsed_time < 300.0, (
            f"Analysis took {elapsed_time:.1f}s - exceeds 300s timeout. "
            f"Performance optimization needed for production use."
        )

        assert result.is_protected, "Analysis failed to complete successfully"
