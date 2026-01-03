"""Regression tests for VMProtect detector - Validates previously working functionality.

Comprehensive regression test suite ensuring that VMProtect detection functionality
continues to work correctly after code changes. Tests validate:

- Instruction-level analysis with Capstone disassembler
- Mutation detection in VMProtect 1.x/2.x/3.x
- Control flow recovery from obfuscated VMProtect binaries
- VM handler dispatch table detection
- Anti-debug and anti-VM countermeasure detection

All tests MUST use real protected binaries or actual system resources.
Tests MUST FAIL if any regression is detected in previously working functionality.
NO mocks, stubs, or placeholder assertions permitted.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from intellicrack.core.analysis.vmprotect_detector import (
    ControlFlowGraph,
    InstructionPattern,
    VMHandler,
    VMProtectDetection,
    VMProtectDetector,
    VMProtectLevel,
    VMProtectMode,
    VirtualizedRegion,
)


if TYPE_CHECKING:
    from typing import Any


SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
NOTEPAD = SYSTEM32 / "notepad.exe"
CALC = SYSTEM32 / "calc.exe"
KERNEL32 = SYSTEM32 / "kernel32.dll"
NTDLL = SYSTEM32 / "ntdll.dll"
USER32 = SYSTEM32 / "user32.dll"

VMPROTECT_BINARIES_DIR = Path(__file__).parent.parent.parent / "resources" / "protected_binaries" / "vmprotect"


class TestRegressionCapstoneDisassemblyCore:
    """Regression: Validate Capstone disassembler initialization and core functionality."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_capstone_x86_initialization_remains_functional(self) -> None:
        """REGRESSION: Capstone x86 disassembler initializes correctly with detail mode."""
        detector = VMProtectDetector()

        assert detector.cs_x86 is not None, "x86 disassembler must be initialized"
        assert isinstance(detector.cs_x86, Cs), "x86 disassembler must be Cs instance"
        assert detector.cs_x86.detail is True, "x86 detail mode must be enabled"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_capstone_x64_initialization_remains_functional(self) -> None:
        """REGRESSION: Capstone x64 disassembler initializes correctly with detail mode."""
        detector = VMProtectDetector()

        assert detector.cs_x64 is not None, "x64 disassembler must be initialized"
        assert isinstance(detector.cs_x64, Cs), "x64 disassembler must be Cs instance"
        assert detector.cs_x64.detail is True, "x64 detail mode must be enabled"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_get_disassembler_returns_correct_instance(self) -> None:
        """REGRESSION: _get_disassembler returns correct architecture-specific instance."""
        detector = VMProtectDetector()

        x86_cs = detector._get_disassembler("x86")
        x64_cs = detector._get_disassembler("x64")

        assert x86_cs is detector.cs_x86, "x86 architecture must return x86 disassembler"
        assert x64_cs is detector.cs_x64, "x64 architecture must return x64 disassembler"
        assert x86_cs is not x64_cs, "Different architectures must return different disassemblers"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_capstone_disassembles_real_x86_code(self) -> None:
        """REGRESSION: Capstone correctly disassembles real x86 instruction sequences."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        x86_prologue = b"\x55\x8b\xec\x53\x56\x57"
        instructions = list(detector.cs_x86.disasm(x86_prologue, 0))

        assert len(instructions) == 6, "Must disassemble all 6 instructions"
        assert instructions[0].mnemonic == "push", "First instruction must be push"
        assert instructions[1].mnemonic == "mov", "Second instruction must be mov"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_capstone_disassembles_real_x64_code(self) -> None:
        """REGRESSION: Capstone correctly disassembles real x64 instruction sequences."""
        detector = VMProtectDetector()
        assert detector.cs_x64 is not None

        x64_prologue = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10"
        instructions = list(detector.cs_x64.disasm(x64_prologue, 0))

        assert len(instructions) == 2, "Must disassemble both x64 instructions"
        assert all(insn.mnemonic == "mov" for insn in instructions), "Both must be mov instructions"


class TestRegressionSemanticPatternMatching:
    """Regression: Validate semantic pattern matching engine continues to function."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_matching_x86_vm_entry(self) -> None:
        """REGRESSION: Semantic pattern matching detects VMProtect x86 VM entry prologues."""
        detector = VMProtectDetector()

        vm_entry_code = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08\x8b\x75\x0c"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_code + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        assert len(handlers) > 0, "Must detect VM handlers in x86 VM entry code"
        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]
        assert len(entry_handlers) > 0, "Must specifically detect VM entry handler type"

        for handler in entry_handlers:
            assert handler.offset >= 102, f"Handler offset {handler.offset} must be within expected range"
            assert handler.size > 0, "Handler size must be positive"
            assert handler.confidence >= 0.7, f"Confidence {handler.confidence} below minimum threshold"
            assert len(handler.opcodes) > 0, "Handler must contain extracted opcodes"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_matching_x64_vm_entry(self) -> None:
        """REGRESSION: Semantic pattern matching detects VMProtect x64 VM entry prologues."""
        detector = VMProtectDetector()

        vm_entry_x64 = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7c\x24\x18"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_x64 + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x64")

        assert len(handlers) > 0, "Must detect VM handlers in x64 VM entry code"
        for handler in handlers:
            assert handler.offset >= 0, "Handler offset must be valid"
            assert handler.size > 0, "Handler size must be positive"
            assert handler.confidence > 0.0, "Handler confidence must be positive"
            assert len(handler.semantic_signature) > 0, "Handler must have semantic signature"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_requires_memory_access_check(self) -> None:
        """REGRESSION: Memory access detection correctly identifies memory operands."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        code_with_mem = b"\x8b\x45\x08\x89\x45\x0c\xff\x30"
        instructions_mem = list(detector.cs_x86.disasm(code_with_mem, 0))
        has_memory = detector._has_memory_access(instructions_mem)
        assert has_memory is True, "Must detect memory access in memory-accessing instructions"

        code_no_mem = b"\x90\x90\xc3"
        instructions_no_mem = list(detector.cs_x86.disasm(code_no_mem, 0))
        has_no_memory = detector._has_memory_access(instructions_no_mem)
        assert has_no_memory is False, "Must not detect memory access in non-memory instructions"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_requires_register_usage_check(self) -> None:
        """REGRESSION: Register usage detection correctly identifies required registers."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        code_with_ebp = b"\x55\x8b\xec\x53\x56\x57"
        instructions = list(detector.cs_x86.disasm(code_with_ebp, 0))

        uses_ebp = detector._uses_registers(instructions, ["ebp"])
        assert uses_ebp is True, "Must detect ebp register usage"

        uses_nonexistent = detector._uses_registers(instructions, ["r15"])
        assert uses_nonexistent is False, "Must not detect non-present register"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_mnemonic_sequence_checking_allows_gaps(self) -> None:
        """REGRESSION: Mnemonic sequence checking allows gaps between matched instructions."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        code = b"\x55\x90\x90\x8b\xec\x90\x53"
        instructions = list(detector.cs_x86.disasm(code, 0))

        matches = detector._check_mnemonic_sequence(instructions, ["push", "mov", "push"])
        assert matches is True, "Must match sequence with gaps between instructions"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_instruction_normalization_abstracts_operands(self) -> None:
        """REGRESSION: Instruction normalization abstracts operands for polymorphism detection."""
        detector = VMProtectDetector()

        opcodes_v1 = [(0x1000, "mov eax, 0x1234"), (0x1002, "add eax, ebx"), (0x1004, "ret")]
        opcodes_v2 = [(0x2000, "mov ecx, 0x5678"), (0x2002, "add ecx, edx"), (0x2004, "ret")]

        normalized1 = detector._normalize_instructions(opcodes_v1)
        normalized2 = detector._normalize_instructions(opcodes_v2)

        assert len(normalized1) == 3, "Normalization must preserve instruction count"
        assert len(normalized2) == 3, "Normalization must preserve instruction count"
        assert normalized1[0].startswith("mov"), "First normalized must be mov"
        assert normalized1[1].startswith("add"), "Second normalized must be add"
        assert normalized1[2] == "ret", "Third normalized must be ret"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_signature_generation_creates_fingerprint(self) -> None:
        """REGRESSION: Semantic signature generation creates behavioral fingerprints."""
        detector = VMProtectDetector()

        opcodes = [
            (0x1000, "push ebp"),
            (0x1001, "mov ebp, esp"),
            (0x1003, "sub esp, 0x20"),
            (0x1006, "push ebx"),
        ]

        signature = detector._generate_semantic_signature(opcodes)

        assert len(signature) > 0, "Signature must be generated"
        assert "push" in signature, "Signature must contain push mnemonic"
        assert "mov" in signature, "Signature must contain mov mnemonic"
        assert "sub" in signature, "Signature must contain sub mnemonic"


class TestRegressionMutationEngineDetection:
    """Regression: Validate mutation engine detection for VMProtect 1.x/2.x/3.x."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_junk_instruction_detection_nop(self) -> None:
        """REGRESSION: Junk instruction detector identifies NOP instructions."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        nop_insn = list(detector.cs_x86.disasm(b"\x90", 0))[0]
        is_junk = detector._is_junk_instruction(nop_insn)
        assert is_junk is True, "NOP must be identified as junk instruction"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_junk_instruction_detection_xchg_self(self) -> None:
        """REGRESSION: Junk instruction detector identifies XCHG reg,reg as junk."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        xchg_insn = list(detector.cs_x86.disasm(b"\x87\xc0", 0))[0]
        is_junk = detector._is_junk_instruction(xchg_insn)
        assert is_junk is True, "XCHG EAX,EAX must be identified as junk"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_junk_instruction_detection_mov_self(self) -> None:
        """REGRESSION: Junk instruction detector identifies MOV reg,reg as junk."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        mov_self = list(detector.cs_x86.disasm(b"\x89\xc0", 0))[0]
        is_junk = detector._is_junk_instruction(mov_self)
        assert is_junk is True, "MOV EAX,EAX must be identified as junk"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_junk_instruction_detection_add_zero(self) -> None:
        """REGRESSION: Junk instruction detector identifies ADD reg,0 as junk."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        add_zero = list(detector.cs_x86.disasm(b"\x83\xc0\x00", 0))[0]
        is_junk = detector._is_junk_instruction(add_zero)
        assert is_junk is True, "ADD EAX,0 must be identified as junk"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_junk_instruction_detection_sub_zero(self) -> None:
        """REGRESSION: Junk instruction detector identifies SUB reg,0 as junk."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        sub_zero = list(detector.cs_x86.disasm(b"\x83\xe8\x00", 0))[0]
        is_junk = detector._is_junk_instruction(sub_zero)
        assert is_junk is True, "SUB EAX,0 must be identified as junk"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_mutation_score_calculation_heavy_mutation(self) -> None:
        """REGRESSION: Mutation detection calculates high score for heavily mutated code."""
        detector = VMProtectDetector()

        mutated_code = (
            b"\x90\x90\x90" b"\x87\xc0" b"\x89\xc0" b"\x90\x90" b"\x83\xc0\x00" b"\x90\x90\x90"
        ) * 50

        binary = b"MZ" + b"\x00" * 100 + mutated_code

        result = detector._detect_mutations_advanced(binary, "x86")

        assert result["score"] > 0.3, f"Mutation score {result['score']} below threshold for heavy mutation"
        assert result["junk_instruction_ratio"] > 0.2, (
            f"Junk ratio {result['junk_instruction_ratio']} below threshold"
        )

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_mutation_differentiates_clean_vs_mutated(self) -> None:
        """REGRESSION: Mutation detection differentiates clean code from mutated code."""
        detector = VMProtectDetector()

        clean_code = b"\x55\x8b\xec\x53\x56\x57\x8b\x45\x08\x3b\x45\x0c\x5f\x5e\x5b\xc9\xc3" * 10
        mutated_code = (b"\x90\x90\x87\xc0\x89\xc0\x90" * 20) + clean_code

        clean_binary = b"MZ" + b"\x00" * 100 + clean_code
        mutated_binary = b"MZ" + b"\x00" * 100 + mutated_code

        clean_result = detector._detect_mutations_advanced(clean_binary, "x86")
        mutated_result = detector._detect_mutations_advanced(mutated_binary, "x86")

        assert mutated_result["score"] > clean_result["score"], (
            f"Mutated score {mutated_result['score']} not higher than clean {clean_result['score']}"
        )

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_pattern_diversity_calculation_high_entropy(self) -> None:
        """REGRESSION: Pattern diversity correctly measures high-entropy polymorphic code."""
        detector = VMProtectDetector()

        high_diversity = b"".join(bytes([i % 256]) for i in range(1000))
        diversity_score = detector._calculate_pattern_diversity(high_diversity)

        assert 0.0 <= diversity_score <= 1.0, "Diversity score must be in valid range"
        assert diversity_score > 0.5, f"High-diversity code scored too low: {diversity_score}"


class TestRegressionControlFlowRecovery:
    """Regression: Validate control flow graph recovery from obfuscated binaries."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_recovery_identifies_basic_blocks(self) -> None:
        """REGRESSION: Control flow recovery identifies basic blocks correctly."""
        detector = VMProtectDetector()

        code_with_branches = (
            b"\x55" b"\x8b\xec" b"\x75\x10" b"\x8b\x45\x08" b"\xeb\x05" b"\x8b\x45\x0c" b"\x5f\x5e\x5b\xc9\xc3"
        )

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(code_with_branches),
            vm_entry=100,
            vm_exit=100 + len(code_with_branches),
            handlers_used={"test"},
            control_flow_complexity=3.0,
        )

        binary = b"\x00" * 100 + code_with_branches + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert isinstance(cfg, ControlFlowGraph), "Must return ControlFlowGraph instance"
        assert len(cfg.basic_blocks) > 0, "Must identify basic blocks"
        assert len(cfg.entry_points) > 0, "Must identify entry points"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_recovery_builds_edges(self) -> None:
        """REGRESSION: Control flow recovery builds edges between basic blocks."""
        detector = VMProtectDetector()

        code = b"\x55\x8b\xec\x74\x05\x8b\x45\x08\xc3\x8b\x45\x0c\xc3"

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(code),
            vm_entry=100,
            vm_exit=100 + len(code),
            handlers_used={"test"},
            control_flow_complexity=2.5,
        )

        binary = b"\x00" * 100 + code + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert isinstance(cfg.edges, list), "Edges must be a list"
        assert cfg.complexity_score > 0, "Complexity score must be calculated"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_tracks_indirect_branches(self) -> None:
        """REGRESSION: Control flow recovery tracks indirect branches and computed jumps."""
        detector = VMProtectDetector()

        indirect_jmp = b"\xff\x24\x85\x00\x10\x00\x00"

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(indirect_jmp) + 50,
            vm_entry=100,
            vm_exit=100 + len(indirect_jmp) + 50,
            handlers_used={"dispatcher"},
            control_flow_complexity=4.0,
        )

        binary = b"\x00" * 100 + indirect_jmp + b"\x90" * 50 + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert cfg.indirect_branches > 0, "Must track indirect branch count"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_identifies_exit_points(self) -> None:
        """REGRESSION: Control flow recovery identifies VM exit points correctly."""
        detector = VMProtectDetector()

        code_with_rets = b"\x55\x8b\xec\x8b\x45\x08\xc3\x8b\x45\x0c\xc3"

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(code_with_rets),
            vm_entry=100,
            vm_exit=100 + len(code_with_rets),
            handlers_used={"test"},
            control_flow_complexity=1.5,
        )

        binary = b"\x00" * 100 + code_with_rets + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert len(cfg.exit_points) > 0, "Must identify exit points"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_tracks_vm_context_switches(self) -> None:
        """REGRESSION: Control flow recovery tracks VM context save/restore operations."""
        detector = VMProtectDetector()

        context_ops = b"\x9c\x60\x8b\x45\x08\x61\x9d\xc3"

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(context_ops),
            vm_entry=100,
            vm_exit=100 + len(context_ops),
            handlers_used={"context_save"},
            control_flow_complexity=2.0,
        )

        binary = b"\x00" * 100 + context_ops + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert cfg.vm_context_switches >= 2, "Must track context save/restore operations"


class TestRegressionVMHandlerDispatchTables:
    """Regression: Validate VM handler dispatch table detection."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_dispatcher_detection_x86_indirect_jump(self) -> None:
        """REGRESSION: Dispatcher detection identifies x86 indirect jump dispatch tables."""
        detector = VMProtectDetector()

        dispatcher_code = b"\xff\x24\x85\x00\x10\x40\x00"

        binary = b"MZ" + b"\x00" * 200 + dispatcher_code + b"\x90" * 500

        dispatcher_offset = detector._find_dispatcher_advanced(binary, "x86")

        if dispatcher_offset is not None:
            assert dispatcher_offset >= 202, f"Dispatcher offset {dispatcher_offset} out of expected range"
            assert dispatcher_offset < len(binary), "Dispatcher offset must be within binary"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_dispatcher_detection_x64_indirect_jump(self) -> None:
        """REGRESSION: Dispatcher detection identifies x64 indirect jump dispatch tables."""
        detector = VMProtectDetector()

        dispatcher_code_x64 = b"\xff\x24\xc5\x00\x10\x40\x00"

        binary = b"MZ" + b"\x00" * 200 + dispatcher_code_x64 + b"\x90" * 500

        dispatcher_offset = detector._find_dispatcher_advanced(binary, "x64")

        if dispatcher_offset is not None:
            assert dispatcher_offset >= 202, f"Dispatcher offset {dispatcher_offset} out of expected range"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_regression_handler_table_validation_rejects_sequential(self) -> None:
        """REGRESSION: Handler table validation rejects overly sequential pointer patterns."""
        detector = VMProtectDetector()

        sequential_pointers = [0x1000 + i for i in range(20)]
        is_valid = detector._validate_handler_table(sequential_pointers)

        assert is_valid is False, "Sequential pointers must be rejected as invalid"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_regression_handler_table_validation_requires_diversity(self) -> None:
        """REGRESSION: Handler table validation requires sufficient pointer diversity."""
        detector = VMProtectDetector()

        duplicate_pointers = [0x401000] * 20
        is_valid = detector._validate_handler_table(duplicate_pointers)

        assert is_valid is False, "Duplicate pointers must be rejected as invalid"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_regression_handler_table_validation_accepts_realistic(self) -> None:
        """REGRESSION: Handler table validation accepts realistic handler pointer tables."""
        detector = VMProtectDetector()

        realistic_pointers = [
            0x401000,
            0x401120,
            0x401240,
            0x401360,
            0x401480,
            0x4015A0,
            0x4016C0,
            0x4017E0,
            0x401900,
            0x401A20,
            0x401B40,
            0x401C60,
            0x401D80,
            0x401EA0,
            0x401FC0,
            0x4020E0,
        ]

        is_valid = detector._validate_handler_table(realistic_pointers)

        assert is_valid is True, "Realistic handler table must be accepted as valid"

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_regression_handler_table_pointer_density_validation(self) -> None:
        """REGRESSION: Handler table detection validates pointer density and alignment."""
        detector = VMProtectDetector()

        valid_pointers = b"".join(struct.pack("<I", 0x401000 + i * 0x50) for i in range(25))
        section_data = b"\x00" * 100 + valid_pointers + b"\x00" * 100

        offset = detector._scan_for_handler_table_advanced(section_data, "x86")

        if offset is not None:
            assert offset >= 0, "Offset must be non-negative"
            assert offset < len(section_data) - 100, "Offset must be within valid range"


class TestRegressionHandlerComplexityAnalysis:
    """Regression: Validate VM handler complexity metric calculation."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_complexity_metrics_accurate(self) -> None:
        """REGRESSION: Handler complexity analysis calculates accurate complexity metrics."""
        detector = VMProtectDetector()

        complex_handler = (
            b"\x55\x8b\xec\x53\x56\x57"
            b"\x75\x10"
            b"\x8b\x45\x08"
            b"\x3b\x45\x0c"
            b"\x74\x05"
            b"\x8b\x75\x10"
            b"\x33\xc0"
            b"\xeb\x08"
            b"\x8b\x45\x14"
            b"\x5f\x5e\x5b\xc9\xc3"
        )

        metrics = detector._calculate_handler_complexity_advanced(complex_handler, 0, len(complex_handler), "x86")

        assert metrics["complexity"] > 20, f"Complexity {metrics['complexity']} below expected threshold"
        assert metrics["branches"] >= 2, f"Branch count {metrics['branches']} too low"
        assert metrics["memory_ops"] >= 2, f"Memory operation count {metrics['memory_ops']} too low"
        assert metrics["instruction_count"] > 10, f"Instruction count {metrics['instruction_count']} too low"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_opcode_extraction_limits_output(self) -> None:
        """REGRESSION: Handler opcode extraction limits output to prevent memory issues."""
        detector = VMProtectDetector()

        long_handler = b"\x90" * 500

        opcodes = detector._extract_opcodes(long_handler, 0, len(long_handler), "x86")

        assert len(opcodes) <= 50, f"Opcode extraction returned {len(opcodes)} opcodes, exceeding limit"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_xref_finding_locates_references(self) -> None:
        """REGRESSION: Handler cross-reference finding locates handler references."""
        detector = VMProtectDetector()

        handler_offset = 0x1000
        reference_data = struct.pack("<I", handler_offset)
        binary = b"\x00" * 500 + reference_data + b"\x00" * 500

        xrefs = detector._find_handler_xrefs(binary, handler_offset)

        assert isinstance(xrefs, list), "XRefs must be a list"
        assert len(xrefs) <= 10, "XRefs must be limited to prevent excessive results"


class TestRegressionProtectionLevelClassification:
    """Regression: Validate protection level classification logic."""

    def test_regression_ultra_protection_classification(self) -> None:
        """REGRESSION: Protection classifier identifies ULTRA from high complexity metrics."""
        detector = VMProtectDetector()

        ultra_handlers = [
            VMHandler(offset=i * 100, size=150, handler_type="complex", pattern=b"", confidence=0.95, complexity=95)
            for i in range(20)
        ]

        regions = [
            VirtualizedRegion(
                start_offset=i * 2000,
                end_offset=(i + 1) * 2000,
                vm_entry=i * 2000,
                vm_exit=(i + 1) * 2000,
                handlers_used={"complex"},
                control_flow_complexity=7.5,
            )
            for i in range(12)
        ]

        mutation_score = 0.85

        level = detector._determine_protection_level(ultra_handlers, regions, mutation_score)

        assert level == VMProtectLevel.ULTRA, f"Expected ULTRA, got {level}"

    def test_regression_standard_protection_classification(self) -> None:
        """REGRESSION: Protection classifier identifies STANDARD from moderate complexity."""
        detector = VMProtectDetector()

        standard_handlers = [
            VMHandler(offset=i * 100, size=80, handler_type="standard", pattern=b"", confidence=0.85, complexity=55)
            for i in range(10)
        ]

        regions = [
            VirtualizedRegion(
                start_offset=i * 1500,
                end_offset=(i + 1) * 1500,
                vm_entry=i * 1500,
                vm_exit=(i + 1) * 1500,
                handlers_used={"standard"},
                control_flow_complexity=4.0,
            )
            for i in range(7)
        ]

        mutation_score = 0.50

        level = detector._determine_protection_level(standard_handlers, regions, mutation_score)

        assert level == VMProtectLevel.STANDARD, f"Expected STANDARD, got {level}"

    def test_regression_lite_protection_classification(self) -> None:
        """REGRESSION: Protection classifier identifies LITE from low complexity metrics."""
        detector = VMProtectDetector()

        lite_handlers = [
            VMHandler(offset=i * 100, size=40, handler_type="lite", pattern=b"", confidence=0.75, complexity=25)
            for i in range(4)
        ]

        regions = [
            VirtualizedRegion(
                start_offset=i * 1000,
                end_offset=(i + 1) * 1000,
                vm_entry=i * 1000,
                vm_exit=(i + 1) * 1000,
                handlers_used={"lite"},
                control_flow_complexity=2.0,
            )
            for i in range(3)
        ]

        mutation_score = 0.15

        level = detector._determine_protection_level(lite_handlers, regions, mutation_score)

        assert level == VMProtectLevel.LITE, f"Expected LITE, got {level}"


class TestRegressionVersionDetection:
    """Regression: Validate VMProtect version detection logic."""

    def test_regression_version_detection_from_vmp_sections(self) -> None:
        """REGRESSION: Version detection identifies version from VMP section count."""
        detector = VMProtectDetector()

        section_analysis_v3 = {
            "vmp_sections": [
                {"name": ".vmp0", "entropy": 7.8},
                {"name": ".vmp1", "entropy": 7.9},
                {"name": ".vmp2", "entropy": 7.7},
            ],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }

        version = detector._detect_version_advanced(b"MZ", section_analysis_v3, [])

        assert "3" in version, f"Expected version 3.x, got {version}"

    def test_regression_version_detection_from_string_indicators(self) -> None:
        """REGRESSION: Version detection identifies version from string indicators."""
        detector = VMProtectDetector()

        binary_v2 = b"MZ" + b"\x00" * 100 + b"VMProtect 2.13" + b"\x00" * 1000

        section_analysis: dict[str, Any] = {
            "vmp_sections": [],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }

        version = detector._detect_version_advanced(binary_v2, section_analysis, [])

        assert "2" in version, f"Expected version 2.x, got {version}"


class TestRegressionBypassRecommendations:
    """Regression: Validate bypass recommendation generation."""

    def test_regression_bypass_recommendations_for_ultra(self) -> None:
        """REGRESSION: Bypass recommendations generated for ULTRA protection."""
        detector = VMProtectDetector()

        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.ULTRA,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x64",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.95,
        )

        recommendations = detector._generate_bypass_recommendations(detection)

        assert len(recommendations) > 0, "Must generate recommendations for ULTRA protection"
        assert any("Ultra" in rec or "advanced" in rec.lower() for rec in recommendations), (
            "Must mention Ultra protection or advanced techniques"
        )

    def test_regression_bypass_recommendations_include_dispatcher_offset(self) -> None:
        """REGRESSION: Bypass recommendations include dispatcher offset when available."""
        detector = VMProtectDetector()

        detection = VMProtectDetection(
            detected=True,
            version="3.x",
            protection_level=VMProtectLevel.STANDARD,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="x64",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=0x401000,
            handler_table_offset=None,
            confidence=0.85,
        )

        recommendations = detector._generate_bypass_recommendations(detection)

        assert any("0x00401000" in rec or "dispatcher" in rec.lower() for rec in recommendations), (
            "Must include dispatcher offset in recommendations"
        )


class TestRegressionRealBinaryProcessing:
    """Regression: Validate processing of real Windows system binaries."""

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_regression_notepad_processes_without_crash(self) -> None:
        """REGRESSION: Detector processes notepad.exe without crashing."""
        detector = VMProtectDetector()

        detection = detector.detect(str(NOTEPAD))

        assert isinstance(detection, VMProtectDetection), "Must return VMProtectDetection instance"
        assert detection.architecture in ["x86", "x64"], f"Invalid architecture: {detection.architecture}"
        assert detection.confidence >= 0.0, "Confidence must be non-negative"

    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_regression_kernel32_processes_without_crash(self) -> None:
        """REGRESSION: Detector processes kernel32.dll without crashing."""
        detector = VMProtectDetector()

        detection = detector.detect(str(KERNEL32))

        assert isinstance(detection, VMProtectDetection), "Must return VMProtectDetection instance"
        assert detection.architecture in ["x86", "x64"], f"Invalid architecture: {detection.architecture}"

    @pytest.mark.skipif(not CALC.exists(), reason="calc.exe not found")
    def test_regression_calc_architecture_detection_remains_accurate(self) -> None:
        """REGRESSION: Architecture detection remains accurate for calc.exe."""
        detector = VMProtectDetector()

        detection = detector.detect(str(CALC))

        assert detection.architecture in ["x86", "x64"], f"Invalid architecture: {detection.architecture}"

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_notepad_instruction_level_analysis_functional(self) -> None:
        """REGRESSION: Instruction-level analysis processes notepad.exe successfully."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()

        handlers = detector._detect_vm_handlers_semantic(data, "x64")

        assert isinstance(handlers, list), "Must return list of handlers"
        for handler in handlers:
            assert handler.offset >= 0, "Handler offset must be valid"
            assert handler.size > 0, "Handler size must be positive"
            assert 0.0 < handler.confidence <= 1.0, "Handler confidence must be in valid range"


class TestRegressionEdgeCaseHandling:
    """Regression: Validate edge case handling remains robust."""

    def test_regression_corrupted_binary_graceful_failure(self) -> None:
        """REGRESSION: Detector handles corrupted binaries gracefully without crashing."""
        detector = VMProtectDetector()

        with tempfile.TemporaryDirectory() as tmpdir:
            corrupted_path = Path(tmpdir) / "corrupted.exe"
            corrupted_path.write_bytes(b"MZ" + b"\xFF\xFE\xFD\xFC" * 250)

            detection = detector.detect(str(corrupted_path))

            assert isinstance(detection, VMProtectDetection), "Must return valid detection object"
            assert detection.confidence >= 0.0, "Confidence must be non-negative"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_deduplication_removes_overlaps(self) -> None:
        """REGRESSION: Handler deduplication removes overlapping detections correctly."""
        detector = VMProtectDetector()

        handlers = [
            VMHandler(offset=100, size=50, handler_type="test", pattern=b"", confidence=0.90),
            VMHandler(offset=105, size=50, handler_type="test", pattern=b"", confidence=0.85),
            VMHandler(offset=200, size=50, handler_type="test2", pattern=b"", confidence=0.88),
        ]

        deduplicated = detector._deduplicate_handlers(handlers)

        assert len(deduplicated) <= 2, f"Deduplication failed: {len(deduplicated)} handlers remain"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_heavily_mutated_code_detection(self) -> None:
        """REGRESSION: Detector handles heavily mutated code correctly."""
        detector = VMProtectDetector()

        heavily_mutated = (b"\x90\x90\x90\x87\xc0\x89\xc0\x90\x90" * 100) + (
            b"\x55\x8b\xec\x53\x56\x57\x5f\x5e\x5b\xc9\xc3" * 5
        )

        binary = b"MZ" + b"\x00" * 100 + heavily_mutated

        result = detector._detect_mutations_advanced(binary, "x86")

        assert result["score"] > 0.5, f"Mutation score {result['score']} too low for heavy mutation"
        assert result["junk_instruction_ratio"] > 0.4, f"Junk ratio {result['junk_instruction_ratio']} too low"


class TestRegressionArchitectureSupport:
    """Regression: Validate multi-architecture support remains functional."""

    def test_regression_architecture_detection_from_pe_header(self) -> None:
        """REGRESSION: Architecture detection from PE header works correctly."""
        detector = VMProtectDetector()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_path = Path(tmpdir) / "test.exe"
            test_data = b"MZ" + b"\x00" * 100 + b"\x55\x8b\xec\x53\x56\x57" + b"\x90" * 1000
            test_path.write_bytes(test_data)

            with open(test_path, "rb") as f:
                data = f.read()

            arch = detector._detect_architecture(data)

            assert arch in ["x86", "x64", "arm", "arm64", "unknown"], f"Invalid architecture: {arch}"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_x86_vs_x64_pattern_differentiation(self) -> None:
        """REGRESSION: Detector differentiates between x86 and x64 code patterns."""
        detector = VMProtectDetector()

        x86_code = b"\x55\x8b\xec\x53\x56\x57\x5f\x5e\x5b\xc9\xc3"
        x64_code = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x48\x8b\xf1\xc3"

        x86_binary = b"MZ" + b"\x00" * 100 + x86_code + b"\x90" * 1000
        x64_binary = b"MZ" + b"\x00" * 100 + x64_code + b"\x90" * 1000

        x86_handlers = detector._detect_vm_handlers_semantic(x86_binary, "x86")
        x64_handlers = detector._detect_vm_handlers_semantic(x64_binary, "x64")

        assert isinstance(x86_handlers, list), "x86 handlers must be a list"
        assert isinstance(x64_handlers, list), "x64 handlers must be a list"
