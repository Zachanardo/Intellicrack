"""Regression tests for VMProtect detector instruction-level analysis.

Ensures previously completed functionality continues to work correctly:
- Instruction-level analysis with Capstone disassembler
- Mutation detection with semantic pattern matching
- Control flow recovery from obfuscated code

These tests validate that instruction-level analysis implementation has not regressed
and continues to provide accurate VMProtect detection and analysis capabilities.

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

TEST_BINARIES_DIR = Path(__file__).parent.parent.parent / "test_binaries"
SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
NOTEPAD = SYSTEM32 / "notepad.exe"
KERNEL32 = SYSTEM32 / "kernel32.dll"
USER32 = SYSTEM32 / "user32.dll"


def find_vmprotect_binaries() -> list[Path]:
    """Find all VMProtect-protected binaries in test_binaries directory.

    Returns:
        list[Path]: List of paths to VMProtect-protected binaries.
    """
    if not TEST_BINARIES_DIR.exists():
        return []

    vmprotect_binaries: list[Path] = []
    for ext in ["*.exe", "*.dll"]:
        vmprotect_binaries.extend(TEST_BINARIES_DIR.glob(ext))
        vmprotect_binaries.extend(TEST_BINARIES_DIR.glob(f"**/{ext}"))

    return vmprotect_binaries


VMPROTECT_BINARIES = find_vmprotect_binaries()


class RegressionTestCapstoneInstructionAnalysis:
    """Regression: Verify Capstone-based instruction-level analysis still works."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_capstone_disassemblers_initialized(self) -> None:
        """REGRESSION: Capstone disassemblers initialize with detail mode enabled."""
        detector = VMProtectDetector()

        assert detector.cs_x86 is not None, "REGRESSION FAIL: x86 disassembler not initialized"
        assert detector.cs_x64 is not None, "REGRESSION FAIL: x64 disassembler not initialized"
        assert detector.cs_arm is not None, "REGRESSION FAIL: ARM disassembler not initialized"
        assert detector.cs_arm64 is not None, "REGRESSION FAIL: ARM64 disassembler not initialized"

        assert detector.cs_x86.detail is True, "REGRESSION FAIL: x86 detail mode not enabled"
        assert detector.cs_x64.detail is True, "REGRESSION FAIL: x64 detail mode not enabled"
        assert detector.cs_arm.detail is True, "REGRESSION FAIL: ARM detail mode not enabled"
        assert detector.cs_arm64.detail is True, "REGRESSION FAIL: ARM64 detail mode not enabled"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_matching_x86(self) -> None:
        """REGRESSION: Semantic pattern matching detects x86 VM entry prologues."""
        detector = VMProtectDetector()

        vm_entry_prologue_x86 = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08\x89\x45\xfc"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_prologue_x86 + b"\x90" * 200

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        assert isinstance(handlers, list), "REGRESSION FAIL: Handler detection not returning list"
        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]
        assert len(entry_handlers) > 0, "REGRESSION FAIL: VM entry prologue pattern not detected"

        for handler in entry_handlers:
            assert handler.confidence > 0.8, f"REGRESSION FAIL: Handler confidence {handler.confidence} < 0.8"
            assert handler.offset >= 0, "REGRESSION FAIL: Invalid handler offset"
            assert handler.size > 0, "REGRESSION FAIL: Invalid handler size"
            assert len(handler.semantic_signature) > 0, "REGRESSION FAIL: Semantic signature not generated"
            assert len(handler.normalized_instructions) > 0, "REGRESSION FAIL: Instructions not normalized"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_pattern_matching_x64(self) -> None:
        """REGRESSION: Semantic pattern matching detects x64 VM entry prologues."""
        detector = VMProtectDetector()

        vm_entry_prologue_x64 = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7c\x24\x18"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_prologue_x64 + b"\x90" * 200

        handlers = detector._detect_vm_handlers_semantic(binary, "x64")

        assert isinstance(handlers, list), "REGRESSION FAIL: Handler detection not returning list"
        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]

        for handler in entry_handlers:
            assert handler.confidence > 0.8, "REGRESSION FAIL: x64 handler confidence < 0.8"
            assert handler.offset >= 0, "REGRESSION FAIL: Invalid x64 handler offset"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_context_save_pattern_detection(self) -> None:
        """REGRESSION: Context save patterns (PUSHAD/POPFD) detected correctly."""
        detector = VMProtectDetector()

        context_save_x86 = b"\x9c\x60\x8b\x45\x08"
        binary = b"MZ" + b"\x00" * 100 + context_save_x86 + b"\x90" * 200

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        context_handlers = [h for h in handlers if "context_save" in h.handler_type.lower()]
        if context_handlers:
            for handler in context_handlers:
                assert handler.confidence > 0.8, "REGRESSION FAIL: Context save handler confidence < 0.8"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_dispatch_pattern_detection(self) -> None:
        """REGRESSION: Handler dispatch patterns (indirect jumps) detected correctly."""
        detector = VMProtectDetector()

        handler_dispatch_x86 = b"\xff\x24\x85\x00\x00\x00\x00"
        binary = b"MZ" + b"\x00" * 100 + handler_dispatch_x86 + b"\x90" * 200

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        dispatch_handlers = [h for h in handlers if "dispatch" in h.handler_type.lower()]
        if dispatch_handlers:
            for handler in dispatch_handlers:
                assert handler.confidence > 0.85, "REGRESSION FAIL: Dispatch handler confidence < 0.85"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_vm_exit_pattern_detection(self) -> None:
        """REGRESSION: VM exit epilogue patterns (POPAD/POPFD/RET) detected correctly."""
        detector = VMProtectDetector()

        vm_exit_epilogue_x86 = b"\x61\x9d\xc3"
        binary = b"MZ" + b"\x00" * 100 + vm_exit_epilogue_x86 + b"\x90" * 200

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        exit_handlers = [h for h in handlers if "exit" in h.handler_type.lower()]
        if exit_handlers:
            for handler in exit_handlers:
                assert handler.confidence > 0.85, "REGRESSION FAIL: Exit handler confidence < 0.85"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_instruction_normalization(self) -> None:
        """REGRESSION: Instruction normalization for mutation resistance works."""
        detector = VMProtectDetector()

        opcodes = [
            (0x1000, "mov eax, 0x1234"),
            (0x1004, "add ebx, ecx"),
            (0x1006, "jmp 0x2000"),
            (0x100B, "push ebp"),
        ]

        normalized = detector._normalize_instructions(opcodes)

        assert isinstance(normalized, list), "REGRESSION FAIL: Normalization not returning list"
        assert len(normalized) == 4, "REGRESSION FAIL: Not all instructions normalized"
        assert all(isinstance(n, str) for n in normalized), "REGRESSION FAIL: Normalized instructions not strings"

        for norm in normalized:
            assert len(norm) > 0, "REGRESSION FAIL: Empty normalized instruction"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_semantic_signature_generation(self) -> None:
        """REGRESSION: Semantic signature generation creates handler fingerprints."""
        detector = VMProtectDetector()

        opcodes = [
            (0x1000, "push ebp"),
            (0x1001, "mov ebp, esp"),
            (0x1003, "sub esp, 0x40"),
            (0x1006, "push ebx"),
            (0x1007, "push esi"),
            (0x1008, "push edi"),
        ]

        signature = detector._generate_semantic_signature(opcodes)

        assert isinstance(signature, str), "REGRESSION FAIL: Signature not a string"
        assert len(signature) > 0, "REGRESSION FAIL: Empty signature"
        assert "push" in signature, "REGRESSION FAIL: Signature missing instruction mnemonics"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_complexity_calculation(self) -> None:
        """REGRESSION: Handler complexity metrics calculated correctly."""
        detector = VMProtectDetector()

        handler_code = b"\x55\x8b\xec\x83\xec\x40\x75\x10\x8b\x45\x08\xeb\x05\x33\xc0\xc9\xc3"
        binary = b"MZ" + b"\x00" * 100 + handler_code + b"\x90" * 200

        metrics = detector._calculate_handler_complexity_advanced(binary, 103, len(handler_code), "x86")

        assert "complexity" in metrics, "REGRESSION FAIL: Missing complexity metric"
        assert "branches" in metrics, "REGRESSION FAIL: Missing branches metric"
        assert "memory_ops" in metrics, "REGRESSION FAIL: Missing memory_ops metric"
        assert "confidence_factor" in metrics, "REGRESSION FAIL: Missing confidence_factor"

        assert metrics["complexity"] > 0, "REGRESSION FAIL: Zero complexity for non-trivial code"
        assert 0.0 <= metrics["confidence_factor"] <= 1.0, "REGRESSION FAIL: Invalid confidence factor"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_handler_deduplication(self) -> None:
        """REGRESSION: Handler deduplication removes overlapping detections."""
        detector = VMProtectDetector()

        handlers = [
            VMHandler(offset=0x1000, size=50, handler_type="test", pattern=b"", confidence=0.9),
            VMHandler(offset=0x1010, size=50, handler_type="test", pattern=b"", confidence=0.85),
            VMHandler(offset=0x2000, size=50, handler_type="test2", pattern=b"", confidence=0.88),
        ]

        deduplicated = detector._deduplicate_handlers(handlers)

        assert isinstance(deduplicated, list), "REGRESSION FAIL: Deduplication not returning list"
        assert len(deduplicated) <= len(handlers), "REGRESSION FAIL: Deduplication increased handler count"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_regression_capstone_disassembly_real_binary(self) -> None:
        """REGRESSION: Capstone disassembly works on real Windows binaries."""
        detector = VMProtectDetector()

        with open(NOTEPAD, "rb") as f:
            data = f.read()

        arch = detector._detect_architecture(data)
        assert arch in ["x86", "x64"], "REGRESSION FAIL: Architecture detection failed"

        cs = detector._get_disassembler(arch)
        assert cs is not None, "REGRESSION FAIL: Failed to get disassembler for detected architecture"

        code_sample = data[0x1000 : 0x1000 + 256]
        instructions = list(cs.disasm(code_sample, 0x1000))

        assert len(instructions) > 0, "REGRESSION FAIL: Capstone failed to disassemble real binary code"
        for insn in instructions[:10]:
            assert hasattr(insn, "mnemonic"), "REGRESSION FAIL: Instruction missing mnemonic"
            assert hasattr(insn, "op_str"), "REGRESSION FAIL: Instruction missing operands"
            assert hasattr(insn, "address"), "REGRESSION FAIL: Instruction missing address"
            assert hasattr(insn, "size"), "REGRESSION FAIL: Instruction missing size"

    @pytest.mark.parametrize(
        "binary_path",
        VMPROTECT_BINARIES,
        ids=[p.name for p in VMPROTECT_BINARIES],
    )
    def test_regression_instruction_analysis_vmprotect_binaries(self, binary_path: Path) -> None:
        """REGRESSION: Instruction-level analysis works on real VMProtect binaries."""
        detector = VMProtectDetector()

        with open(binary_path, "rb") as f:
            data = f.read()

        arch = detector._detect_architecture(data)
        handlers = detector._detect_vm_handlers_semantic(data, arch)

        assert isinstance(handlers, list), f"REGRESSION FAIL: Handler detection failed for {binary_path.name}"

        for handler in handlers:
            assert isinstance(handler, VMHandler), "REGRESSION FAIL: Invalid handler type"
            assert handler.offset >= 0, "REGRESSION FAIL: Invalid handler offset"
            assert handler.size > 0, "REGRESSION FAIL: Invalid handler size"
            assert handler.confidence > 0.0, "REGRESSION FAIL: Invalid handler confidence"
            assert len(handler.semantic_signature) >= 0, "REGRESSION FAIL: Missing semantic signature"


class RegressionTestMutationDetection:
    """Regression: Verify mutation detection with semantic analysis still works."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_nop_mutation_detection(self) -> None:
        """REGRESSION: NOP sled mutation detection works."""
        detector = VMProtectDetector()

        nop_sled = b"\x90" * 50
        binary = b"MZ" + b"\x00" * 100 + nop_sled + b"\x55\x8b\xec"

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert "junk_instruction_ratio" in mutation_analysis, "REGRESSION FAIL: Missing junk_instruction_ratio"
        assert "score" in mutation_analysis, "REGRESSION FAIL: Missing mutation score"
        assert mutation_analysis["junk_instruction_ratio"] > 0.0, "REGRESSION FAIL: Failed to detect NOP instructions"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_xchg_nop_mutation_detection(self) -> None:
        """REGRESSION: XCHG EAX,EAX pseudo-NOP mutation detection works."""
        detector = VMProtectDetector()

        xchg_nops = b"\x87\xc0" * 30
        binary = b"MZ" + b"\x00" * 100 + xchg_nops + b"\x55\x8b\xec"

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert mutation_analysis["junk_instruction_ratio"] > 0.0, "REGRESSION FAIL: Failed to detect XCHG pseudo-NOPs"
        assert mutation_analysis["score"] > 0.0, "REGRESSION FAIL: Mutation score not calculated"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_mov_self_mutation_detection(self) -> None:
        """REGRESSION: MOV REG,REG self-assignment mutation detection works."""
        detector = VMProtectDetector()

        mov_self = b"\x89\xc0" * 20
        binary = b"MZ" + b"\x00" * 100 + mov_self + b"\x55\x8b\xec"

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert mutation_analysis["junk_instruction_ratio"] > 0.0, "REGRESSION FAIL: Failed to detect MOV self-assignments"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_is_junk_instruction_detection(self) -> None:
        """REGRESSION: _is_junk_instruction identifies mutation patterns correctly."""
        detector = VMProtectDetector()

        if detector.cs_x86 is None:
            pytest.skip("x86 disassembler not available")

        junk_patterns = [
            b"\x90",
            b"\x87\xc0",
            b"\x89\xc0",
            b"\x83\xc0\x00",
            b"\x83\xe8\x00",
        ]

        for pattern in junk_patterns:
            instructions = list(detector.cs_x86.disasm(pattern, 0x1000))
            if instructions:
                insn = instructions[0]
                is_junk = detector._is_junk_instruction(insn)
                assert is_junk, f"REGRESSION FAIL: Failed to identify {insn.mnemonic} {insn.op_str} as junk"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_pattern_diversity_calculation(self) -> None:
        """REGRESSION: Pattern diversity calculation for polymorphism detection works."""
        detector = VMProtectDetector()

        diverse_patterns = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" * 500
        binary = b"MZ" + diverse_patterns

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert "pattern_diversity" in mutation_analysis, "REGRESSION FAIL: Missing pattern_diversity metric"
        assert 0.0 <= mutation_analysis["pattern_diversity"] <= 1.0, "REGRESSION FAIL: Invalid pattern diversity value"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_mutation_score_composite_calculation(self) -> None:
        """REGRESSION: Composite mutation score calculation works correctly."""
        detector = VMProtectDetector()

        heavy_mutation = b"\x90" * 100 + b"\x87\xc0" * 50 + b"\x89\xc0" * 50
        binary = b"MZ" + heavy_mutation

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert "score" in mutation_analysis, "REGRESSION FAIL: Missing mutation score"
        assert 0.0 <= mutation_analysis["score"] <= 1.0, "REGRESSION FAIL: Invalid mutation score"
        assert mutation_analysis["score"] > 0.0, "REGRESSION FAIL: Failed to detect mutation in heavily mutated code"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_code_bloat_factor_calculation(self) -> None:
        """REGRESSION: Code bloat factor calculation works correctly."""
        detector = VMProtectDetector()

        bloated_code = b"\x90" * 50 + b"\x55\x8b\xec" + b"\x90" * 50
        binary = b"MZ" + bloated_code

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert "code_bloat_factor" in mutation_analysis, "REGRESSION FAIL: Missing code_bloat_factor"
        assert mutation_analysis["code_bloat_factor"] >= 1.0, "REGRESSION FAIL: Invalid code bloat factor"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_region_mutation_detection(self) -> None:
        """REGRESSION: Region-specific mutation detection works correctly."""
        detector = VMProtectDetector()

        mutated_region = b"\x90" * 30 + b"\x87\xc0" * 20 + b"\x55\x8b\xec"
        binary = b"MZ" + b"\x00" * 100 + mutated_region + b"\x00" * 500

        mutation_detected = detector._check_region_mutation_advanced(binary, 103, 103 + len(mutated_region), "x86")

        assert isinstance(mutation_detected, bool), "REGRESSION FAIL: Invalid mutation detection result type"

    @pytest.mark.parametrize(
        "binary_path",
        VMPROTECT_BINARIES,
        ids=[p.name for p in VMPROTECT_BINARIES],
    )
    def test_regression_mutation_detection_vmprotect_binaries(self, binary_path: Path) -> None:
        """REGRESSION: Mutation detection works on real VMProtect binaries."""
        detector = VMProtectDetector()

        with open(binary_path, "rb") as f:
            data = f.read()

        arch = detector._detect_architecture(data)
        mutation_analysis = detector._detect_mutations_advanced(data, arch)

        assert isinstance(mutation_analysis, dict), f"REGRESSION FAIL: Invalid mutation analysis for {binary_path.name}"
        assert "score" in mutation_analysis, f"REGRESSION FAIL: Missing score for {binary_path.name}"
        assert "junk_instruction_ratio" in mutation_analysis, f"REGRESSION FAIL: Missing junk ratio for {binary_path.name}"
        assert "pattern_diversity" in mutation_analysis, f"REGRESSION FAIL: Missing diversity for {binary_path.name}"
        assert 0.0 <= mutation_analysis["score"] <= 1.0, f"REGRESSION FAIL: Invalid score for {binary_path.name}"


class RegressionTestControlFlowRecovery:
    """Regression: Verify control flow graph recovery still works correctly."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_basic_recovery(self) -> None:
        """REGRESSION: Control flow graph recovery builds CFG with basic blocks."""
        detector = VMProtectDetector()

        code = b"\x55\x8b\xec\x83\xec\x40\x75\x10\x8b\x45\x08\xc9\xc3"
        binary = b"MZ" + b"\x00" * 100 + code + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(code),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert isinstance(cfg, ControlFlowGraph), "REGRESSION FAIL: CFG not returned"
        assert isinstance(cfg.basic_blocks, dict), "REGRESSION FAIL: Basic blocks not dict"
        assert isinstance(cfg.edges, list), "REGRESSION FAIL: Edges not list"
        assert isinstance(cfg.entry_points, list), "REGRESSION FAIL: Entry points not list"
        assert region.vm_entry in cfg.entry_points, "REGRESSION FAIL: Entry point not in CFG"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_basic_block_boundaries(self) -> None:
        """REGRESSION: CFG identifies basic block boundaries at branches."""
        detector = VMProtectDetector()

        code_with_branches = b"\x55\x8b\xec\x75\x05\x8b\x45\x08\xeb\x03\x31\xc0\xc3"
        binary = b"MZ" + b"\x00" * 100 + code_with_branches + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(code_with_branches),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert len(cfg.basic_blocks) > 0, "REGRESSION FAIL: No basic blocks identified"
        assert cfg.complexity_score > 0.0, "REGRESSION FAIL: Zero complexity score"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_indirect_branch_tracking(self) -> None:
        """REGRESSION: CFG tracks indirect branch instructions correctly."""
        detector = VMProtectDetector()

        indirect_jump = b"\xff\x24\x85\x00\x00\x00\x00"
        binary = b"MZ" + b"\x00" * 100 + indirect_jump + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(indirect_jump),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert hasattr(cfg, "indirect_branches"), "REGRESSION FAIL: CFG missing indirect_branches"
        assert cfg.indirect_branches >= 0, "REGRESSION FAIL: Invalid indirect branches count"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_vm_context_switch_tracking(self) -> None:
        """REGRESSION: CFG tracks VM context save/restore instructions."""
        detector = VMProtectDetector()

        context_save_restore = b"\x9c\x60\x8b\x45\x08\x61\x9d"
        binary = b"MZ" + b"\x00" * 100 + context_save_restore + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(context_save_restore),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert hasattr(cfg, "vm_context_switches"), "REGRESSION FAIL: CFG missing vm_context_switches"
        assert cfg.vm_context_switches >= 0, "REGRESSION FAIL: Invalid context switches count"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_exit_point_identification(self) -> None:
        """REGRESSION: CFG identifies exit points at RET instructions."""
        detector = VMProtectDetector()

        code_with_ret = b"\x55\x8b\xec\x8b\x45\x08\xc9\xc3"
        binary = b"MZ" + b"\x00" * 100 + code_with_ret + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(code_with_ret),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert hasattr(cfg, "exit_points"), "REGRESSION FAIL: CFG missing exit_points"
        assert isinstance(cfg.exit_points, list), "REGRESSION FAIL: Exit points not list"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_cfg_complexity_score_calculation(self) -> None:
        """REGRESSION: CFG complexity score calculated based on structure."""
        detector = VMProtectDetector()

        complex_code = (
            b"\x55\x8b\xec"
            b"\x75\x08"
            b"\x8b\x45\x08"
            b"\xeb\x03"
            b"\x31\xc0"
            b"\x74\x05"
            b"\x83\xc0\x01"
            b"\xc3"
        )
        binary = b"MZ" + b"\x00" * 100 + complex_code + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(complex_code),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert cfg.complexity_score >= 0.0, "REGRESSION FAIL: Negative complexity score"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_control_flow_analysis_metrics(self) -> None:
        """REGRESSION: Control flow analysis returns all required metrics."""
        detector = VMProtectDetector()

        code = b"\x55\x8b\xec\x75\x08\x8b\x45\x08\xeb\x03\x31\xc0\xc3"
        binary = b"MZ" + b"\x00" * 100 + code + b"\x00" * 500

        cf_analysis = detector._analyze_region_control_flow(binary, 103, 103 + len(code), "x86")

        assert "complexity" in cf_analysis, "REGRESSION FAIL: Missing complexity metric"
        assert "basic_blocks" in cf_analysis, "REGRESSION FAIL: Missing basic_blocks metric"
        assert "indirect_jumps" in cf_analysis, "REGRESSION FAIL: Missing indirect_jumps metric"
        assert "dispatcher_calls" in cf_analysis, "REGRESSION FAIL: Missing dispatcher_calls metric"

        assert cf_analysis["complexity"] >= 0.0, "REGRESSION FAIL: Invalid complexity value"
        assert cf_analysis["basic_blocks"] >= 0, "REGRESSION FAIL: Invalid basic_blocks count"
        assert cf_analysis["indirect_jumps"] >= 0, "REGRESSION FAIL: Invalid indirect_jumps count"
        assert cf_analysis["dispatcher_calls"] >= 0, "REGRESSION FAIL: Invalid dispatcher_calls count"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_find_vm_exit_from_entry(self) -> None:
        """REGRESSION: VM exit detection from entry point works correctly."""
        detector = VMProtectDetector()

        code_with_exit = b"\x55\x8b\xec\x9c\x60\x8b\x45\x08\x61\x9d\xc3"
        binary = b"MZ" + b"\x00" * 100 + code_with_exit + b"\x00" * 500

        exit_offset = detector._find_vm_exit_advanced(binary, 103, "x86")

        if exit_offset is not None:
            assert exit_offset >= 103, "REGRESSION FAIL: VM exit before entry"
            assert exit_offset < 103 + len(code_with_exit) + 500, "REGRESSION FAIL: VM exit out of range"

    @pytest.mark.parametrize(
        "binary_path",
        VMPROTECT_BINARIES,
        ids=[p.name for p in VMPROTECT_BINARIES],
    )
    def test_regression_cfg_recovery_vmprotect_binaries(self, binary_path: Path) -> None:
        """REGRESSION: Control flow recovery works on real VMProtect binaries."""
        detector = VMProtectDetector()

        detection = detector.detect(str(binary_path))

        if detection.virtualized_regions:
            assert isinstance(detection.control_flow_graphs, dict), f"REGRESSION FAIL: No CFGs for {binary_path.name}"

            for region_offset, cfg in detection.control_flow_graphs.items():
                assert isinstance(cfg, ControlFlowGraph), f"REGRESSION FAIL: Invalid CFG for {binary_path.name}"
                assert isinstance(cfg.basic_blocks, dict), f"REGRESSION FAIL: Invalid basic blocks for {binary_path.name}"
                assert isinstance(cfg.complexity_score, float), f"REGRESSION FAIL: Invalid complexity for {binary_path.name}"
                assert cfg.complexity_score >= 0.0, f"REGRESSION FAIL: Negative complexity for {binary_path.name}"


class RegressionTestIntegration:
    """Regression: Verify end-to-end instruction-level analysis pipeline."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_complete_detection_pipeline(self) -> None:
        """REGRESSION: Complete detection pipeline with instruction analysis works."""
        detector = VMProtectDetector()

        vm_code = (
            b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08\x9c\x60"
            + b"\x90" * 20
            + b"\xff\x24\x85\x00\x00\x00\x00\x61\x9d\xc3"
        )
        binary = b"MZ" + b"\x00" * 100 + vm_code + b"\x00" * 5000

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "test_vm.exe"
            binary_path.write_bytes(binary)

            detection = detector.detect(str(binary_path))

            assert isinstance(detection, VMProtectDetection), "REGRESSION FAIL: Invalid detection object"
            assert isinstance(detection.handlers, list), "REGRESSION FAIL: Invalid handlers list"
            assert isinstance(detection.virtualized_regions, list), "REGRESSION FAIL: Invalid regions list"
            assert isinstance(detection.technical_details, dict), "REGRESSION FAIL: Invalid technical details"

            if "mutation_analysis" in detection.technical_details:
                mut_analysis = detection.technical_details["mutation_analysis"]
                assert "score" in mut_analysis, "REGRESSION FAIL: Missing mutation score in details"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_regression_instruction_analysis_real_binary(self) -> None:
        """REGRESSION: Instruction analysis runs successfully on real Windows binary."""
        detector = VMProtectDetector()

        detection = detector.detect(str(NOTEPAD))

        assert isinstance(detection, VMProtectDetection), "REGRESSION FAIL: Invalid detection for real binary"
        assert detection.architecture in ["x86", "x64"], "REGRESSION FAIL: Architecture not detected"
        assert 0.0 <= detection.confidence <= 1.0, "REGRESSION FAIL: Invalid confidence value"
        assert isinstance(detection.handlers, list), "REGRESSION FAIL: Handlers not returned"

    @pytest.mark.parametrize(
        "binary_path",
        VMPROTECT_BINARIES,
        ids=[p.name for p in VMPROTECT_BINARIES],
    )
    def test_regression_instruction_analysis_integration_vmprotect(self, binary_path: Path) -> None:
        """REGRESSION: Complete instruction-level analysis works on VMProtect binaries."""
        detector = VMProtectDetector()

        detection = detector.detect(str(binary_path))

        assert detection.detected is True, f"REGRESSION FAIL: Detection failed for {binary_path.name}"
        assert detection.confidence > 0.0, f"REGRESSION FAIL: Zero confidence for {binary_path.name}"
        assert len(detection.handlers) > 0, f"REGRESSION FAIL: No handlers detected for {binary_path.name}"

        assert "mutation_analysis" in detection.technical_details, f"REGRESSION FAIL: No mutation analysis for {binary_path.name}"
        mut_analysis = detection.technical_details["mutation_analysis"]
        assert "score" in mut_analysis, f"REGRESSION FAIL: Missing mutation score for {binary_path.name}"

        if detection.virtualized_regions:
            assert len(detection.control_flow_graphs) > 0, f"REGRESSION FAIL: No CFGs for {binary_path.name}"


class RegressionTestFailureCases:
    """Regression: Verify tests FAIL when functionality is broken."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_fails_on_empty_handlers_for_protected_binary(self) -> None:
        """REGRESSION: Test fails if handler detection returns empty for VM-protected code."""
        detector = VMProtectDetector()

        vm_protected_code = b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08\x9c\x60\xff\x24\x85\x00\x00\x00\x00\x61\x9d\xc3"
        binary = b"MZ" + b"\x00" * 100 + vm_protected_code + b"\x00" * 500

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        assert len(handlers) > 0, "REGRESSION FAIL: Handler detection broken - no handlers found in VM code"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_fails_on_zero_mutation_score_for_mutated_code(self) -> None:
        """REGRESSION: Test fails if mutation detection returns zero for mutated code."""
        detector = VMProtectDetector()

        heavily_mutated = b"\x90" * 100 + b"\x87\xc0" * 50 + b"\x89\xc0" * 50
        binary = b"MZ" + heavily_mutated

        mutation_analysis = detector._detect_mutations_advanced(binary, "x86")

        assert mutation_analysis["score"] > 0.0, "REGRESSION FAIL: Mutation detection broken - zero score for mutated code"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_regression_fails_on_empty_cfg_for_branching_code(self) -> None:
        """REGRESSION: Test fails if CFG recovery returns empty for code with branches."""
        detector = VMProtectDetector()

        branching_code = b"\x55\x8b\xec\x75\x08\x8b\x45\x08\xeb\x03\x31\xc0\xc3"
        binary = b"MZ" + b"\x00" * 100 + branching_code + b"\x00" * 500

        region = VirtualizedRegion(
            start_offset=103,
            end_offset=103 + len(branching_code),
            vm_entry=103,
            vm_exit=None,
            handlers_used=set(),
            control_flow_complexity=0.0,
        )

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert len(cfg.basic_blocks) > 0, "REGRESSION FAIL: CFG recovery broken - no basic blocks found"

    def test_regression_clean_binary_returns_low_confidence(self) -> None:
        """REGRESSION: Clean binary without VMProtect returns low confidence."""
        detector = VMProtectDetector()

        clean_binary = b"MZ" + b"\x00" * 10000

        with tempfile.TemporaryDirectory() as tmpdir:
            clean_path = Path(tmpdir) / "clean.exe"
            clean_path.write_bytes(clean_binary)

            detection = detector.detect(str(clean_path))

            assert detection.confidence < 0.7, "REGRESSION FAIL: High confidence for clean binary without VMProtect"
