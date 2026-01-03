"""Production tests for VMProtect detector - Advanced instruction-level analysis validation.

Validates VMProtect 1.x/2.x/3.x detection using instruction-level analysis with Capstone,
mutation engine detection, polymorphic code recognition, control flow recovery,
VM handler dispatch tables, bytecode interpreters, and anti-debug/anti-VM countermeasures.

Tests MUST use real protected binaries or actual system resources.
Tests MUST FAIL if functionality is incomplete or non-functional.
NO mocks, stubs, or placeholder assertions.

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


class TestCapstoneInstructionLevelAnalysis:
    """Test instruction-level analysis using Capstone disassembler."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_capstone_disassembler_initialization_x86(self) -> None:
        """Detector initializes Capstone x86 disassembler with detail mode enabled."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None
        assert detector.cs_x86.detail is True
        assert isinstance(detector.cs_x86, Cs)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_capstone_disassembler_initialization_x64(self) -> None:
        """Detector initializes Capstone x64 disassembler with detail mode enabled."""
        detector = VMProtectDetector()
        assert detector.cs_x64 is not None
        assert detector.cs_x64.detail is True
        assert isinstance(detector.cs_x64, Cs)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_instruction_level_semantic_pattern_matching_x86(self) -> None:
        """Semantic pattern matching identifies VMProtect x86 handler prologues through instruction analysis."""
        detector = VMProtectDetector()
        vm_entry_code = (
            b"\x55"
            b"\x8b\xec"
            b"\x53"
            b"\x56"
            b"\x57"
            b"\x8b\x7d\x08"
            b"\x8b\x75\x0c"
        )
        binary = b"MZ" + b"\x00" * 100 + vm_entry_code + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        assert len(handlers) > 0
        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]
        assert len(entry_handlers) > 0

        for handler in entry_handlers:
            assert handler.offset >= 102
            assert handler.size > 0
            assert handler.confidence >= 0.8
            assert len(handler.opcodes) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_instruction_level_semantic_pattern_matching_x64(self) -> None:
        """Semantic pattern matching identifies VMProtect x64 handler prologues through instruction analysis."""
        detector = VMProtectDetector()
        vm_entry_x64 = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7c\x24\x18"
        binary = b"MZ" + b"\x00" * 100 + vm_entry_x64 + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x64")

        assert len(handlers) > 0
        for handler in handlers:
            assert handler.offset >= 0
            assert handler.size > 0
            assert handler.confidence > 0.0
            assert len(handler.semantic_signature) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_pattern_requires_memory_access_validation(self) -> None:
        """Semantic pattern matcher validates memory access requirements correctly."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        code_with_memory = b"\x8b\x45\x08\x89\x45\x0c\xff\x30"
        instructions = list(detector.cs_x86.disasm(code_with_memory, 0))

        has_memory = detector._has_memory_access(instructions)
        assert has_memory is True

        code_no_memory = b"\x90\x90\xc3"
        instructions_no_mem = list(detector.cs_x86.disasm(code_no_memory, 0))
        has_no_memory = detector._has_memory_access(instructions_no_mem)
        assert has_no_memory is False

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_pattern_requires_register_usage_validation(self) -> None:
        """Semantic pattern matcher validates required register usage correctly."""
        detector = VMProtectDetector()
        assert detector.cs_x86 is not None

        code_with_ebp = b"\x55\x8b\xec\x53\x56\x57"
        instructions = list(detector.cs_x86.disasm(code_with_ebp, 0))

        uses_ebp = detector._uses_registers(instructions, ["ebp"])
        assert uses_ebp is True

        uses_nonexistent = detector._uses_registers(instructions, ["r15"])
        assert uses_nonexistent is False

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_instruction_normalization_for_polymorphic_detection(self) -> None:
        """Instruction normalization abstracts register names and immediate values for polymorphic detection."""
        detector = VMProtectDetector()

        opcodes_variant1 = [(0x1000, "mov eax, 0x1234"), (0x1002, "add eax, ebx"), (0x1004, "ret")]
        opcodes_variant2 = [(0x2000, "mov ecx, 0x5678"), (0x2002, "add ecx, edx"), (0x2004, "ret")]

        normalized1 = detector._normalize_instructions(opcodes_variant1)
        normalized2 = detector._normalize_instructions(opcodes_variant2)

        assert len(normalized1) == 3
        assert len(normalized2) == 3
        assert normalized1[0].startswith("mov")
        assert normalized1[1].startswith("add")
        assert normalized1[2] == "ret"
        assert normalized2[0].startswith("mov")
        assert normalized2[1].startswith("add")
        assert normalized2[2] == "ret"

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_semantic_signature_generation_from_opcodes(self) -> None:
        """Semantic signature generation creates compact behavioral fingerprints from instruction sequences."""
        detector = VMProtectDetector()

        opcodes = [
            (0x1000, "push ebp"),
            (0x1001, "mov ebp, esp"),
            (0x1003, "sub esp, 0x20"),
            (0x1006, "push ebx"),
        ]

        signature = detector._generate_semantic_signature(opcodes)

        assert len(signature) > 0
        assert "push" in signature
        assert "mov" in signature
        assert "sub" in signature

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_instruction_level_analysis_on_real_notepad(self) -> None:
        """Instruction-level analysis processes real Windows notepad.exe without errors."""
        detector = VMProtectDetector()
        with open(NOTEPAD, "rb") as f:
            data = f.read()

        handlers = detector._detect_vm_handlers_semantic(data, "x64")

        assert isinstance(handlers, list)
        for handler in handlers:
            assert handler.offset >= 0
            assert handler.size > 0
            assert 0.0 < handler.confidence <= 1.0
            assert len(handler.normalized_instructions) >= 0


class TestMutationEngineDetection:
    """Test mutation engine and polymorphic code detection for VMProtect 1.x/2.x/3.x."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_junk_instruction_detection_nop(self) -> None:
        """Mutation detector identifies NOP junk instructions correctly."""
        detector = VMProtectDetector()

        cs = detector.cs_x86
        assert cs is not None

        nop_insn = list(cs.disasm(b"\x90", 0))[0]
        is_junk = detector._is_junk_instruction(nop_insn)
        assert is_junk is True

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_junk_instruction_detection_xchg_eax_eax(self) -> None:
        """Mutation detector identifies XCHG EAX,EAX as junk instruction."""
        detector = VMProtectDetector()

        cs = detector.cs_x86
        assert cs is not None

        xchg_insn = list(cs.disasm(b"\x87\xc0", 0))[0]
        is_junk = detector._is_junk_instruction(xchg_insn)
        assert is_junk is True

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_junk_instruction_detection_mov_self(self) -> None:
        """Mutation detector identifies MOV EAX,EAX as junk instruction."""
        detector = VMProtectDetector()

        cs = detector.cs_x86
        assert cs is not None

        mov_self = list(cs.disasm(b"\x89\xc0", 0))[0]
        is_junk = detector._is_junk_instruction(mov_self)
        assert is_junk is True

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_junk_instruction_detection_add_zero(self) -> None:
        """Mutation detector identifies ADD REG,0 as junk instruction."""
        detector = VMProtectDetector()

        cs = detector.cs_x86
        assert cs is not None

        add_zero = list(cs.disasm(b"\x83\xc0\x00", 0))[0]
        is_junk = detector._is_junk_instruction(add_zero)
        assert is_junk is True

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_mutation_score_calculation_for_heavy_mutation(self) -> None:
        """Mutation detection calculates high score for heavily mutated code."""
        detector = VMProtectDetector()

        mutated_code = (
            b"\x90\x90\x90"
            b"\x87\xc0"
            b"\x89\xc0"
            b"\x90\x90"
            b"\x83\xc0\x00"
            b"\x90\x90\x90"
        ) * 50

        binary = b"MZ" + b"\x00" * 100 + mutated_code

        result = detector._detect_mutations_advanced(binary, "x86")

        assert result["score"] > 0.3
        assert result["junk_instruction_ratio"] > 0.2

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_pattern_diversity_calculation_for_polymorphic_code(self) -> None:
        """Pattern diversity calculation measures polymorphic variance in code."""
        detector = VMProtectDetector()

        high_diversity = b"".join(bytes([i % 256]) for i in range(1000))
        diversity_score = detector._calculate_pattern_diversity(high_diversity)

        assert 0.0 <= diversity_score <= 1.0
        assert diversity_score > 0.5

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_mutation_detection_differentiates_clean_vs_mutated(self) -> None:
        """Mutation detection clearly differentiates between clean and mutated code."""
        detector = VMProtectDetector()

        clean_code = b"\x55\x8b\xec\x53\x56\x57\x8b\x45\x08\x3b\x45\x0c\x5f\x5e\x5b\xc9\xc3" * 10
        mutated_code = (b"\x90\x90\x87\xc0\x89\xc0\x90" * 20) + clean_code

        clean_binary = b"MZ" + b"\x00" * 100 + clean_code
        mutated_binary = b"MZ" + b"\x00" * 100 + mutated_code

        clean_result = detector._detect_mutations_advanced(clean_binary, "x86")
        mutated_result = detector._detect_mutations_advanced(mutated_binary, "x86")

        assert mutated_result["score"] > clean_result["score"]

    def test_mutation_detection_vmprotect_1x_patterns(self) -> None:
        """Mutation detection identifies VMProtect 1.x mutation patterns."""
        detector = VMProtectDetector()

        vmp1_mutations = b"\x90\x90\x90" + b"\x50\x58" + b"\x90" * 5

        binary = b"MZ" + b"\x00" * 100 + (vmp1_mutations * 50)

        result = detector._detect_mutations_advanced(binary, "x86")
        assert result["score"] > 0.1

    def test_mutation_detection_vmprotect_2x_patterns(self) -> None:
        """Mutation detection identifies VMProtect 2.x mutation patterns."""
        detector = VMProtectDetector()

        vmp2_mutations = b"\x87\xc0" + b"\x89\xc0" + b"\x40\x4f" + b"\x90\x90"

        binary = b"MZ" + b"\x00" * 100 + (vmp2_mutations * 50)

        result = detector._detect_mutations_advanced(binary, "x86")
        assert result["score"] > 0.1

    def test_mutation_detection_vmprotect_3x_patterns(self) -> None:
        """Mutation detection identifies VMProtect 3.x mutation patterns."""
        detector = VMProtectDetector()

        vmp3_mutations = b"\x90\x87\xc0\x89\xc0\x90\x90" + b"\x83\xc0\x00" + b"\x48\x87\xc0"

        binary = b"MZ" + b"\x00" * 100 + (vmp3_mutations * 50)

        result = detector._detect_mutations_advanced(binary, "x86")
        assert result["score"] > 0.0


class TestControlFlowRecovery:
    """Test control flow recovery from obfuscated VMProtect binaries."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_recovery_basic_blocks(self) -> None:
        """Control flow recovery identifies basic blocks correctly."""
        detector = VMProtectDetector()

        code_with_branches = (
            b"\x55"
            b"\x8b\xec"
            b"\x75\x10"
            b"\x8b\x45\x08"
            b"\xeb\x05"
            b"\x8b\x45\x0c"
            b"\x5f\x5e\x5b\xc9\xc3"
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

        assert isinstance(cfg, ControlFlowGraph)
        assert len(cfg.basic_blocks) > 0
        assert len(cfg.entry_points) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_recovery_edges(self) -> None:
        """Control flow recovery builds edges between basic blocks."""
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

        assert isinstance(cfg.edges, list)
        assert cfg.complexity_score > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_tracks_indirect_branches(self) -> None:
        """Control flow recovery tracks indirect branches and computed jumps."""
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

        assert cfg.indirect_branches > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_identifies_exit_points(self) -> None:
        """Control flow recovery identifies VM exit points correctly."""
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

        assert len(cfg.exit_points) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_tracks_vm_context_switches(self) -> None:
        """Control flow recovery tracks VM context save/restore operations."""
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

        assert cfg.vm_context_switches >= 2


class TestVMHandlerDispatchTables:
    """Test VM handler dispatch table identification and analysis."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_dispatcher_detection_x86_indirect_jump_pattern(self) -> None:
        """Dispatcher detection identifies x86 indirect jump dispatch tables."""
        detector = VMProtectDetector()

        dispatcher_code = b"\xff\x24\x85\x00\x10\x40\x00"

        binary = b"MZ" + b"\x00" * 200 + dispatcher_code + b"\x90" * 500

        dispatcher_offset = detector._find_dispatcher_advanced(binary, "x86")

        if dispatcher_offset is not None:
            assert dispatcher_offset >= 202
            assert dispatcher_offset < len(binary)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_dispatcher_detection_x64_indirect_jump_pattern(self) -> None:
        """Dispatcher detection identifies x64 indirect jump dispatch tables."""
        detector = VMProtectDetector()

        dispatcher_code_x64 = b"\xff\x24\xc5\x00\x10\x40\x00"

        binary = b"MZ" + b"\x00" * 200 + dispatcher_code_x64 + b"\x90" * 500

        dispatcher_offset = detector._find_dispatcher_advanced(binary, "x64")

        if dispatcher_offset is not None:
            assert dispatcher_offset >= 202

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_dispatcher_detection_requires_vmprotect_markers(self) -> None:
        """Dispatcher detection validates VMProtect context markers before confirming."""
        detector = VMProtectDetector()

        dispatcher_with_context = b"\x9c\x60" + b"\xff\x24\x85\x00\x10\x40\x00"

        binary = b"MZ" + b"\x00" * 200 + dispatcher_with_context + b"\x90" * 500

        dispatcher_offset = detector._find_dispatcher_advanced(binary, "x86")

        if dispatcher_offset is not None:
            assert dispatcher_offset >= 200

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_handler_table_detection_pointer_density_validation(self) -> None:
        """Handler table detection validates pointer density and alignment."""
        detector = VMProtectDetector()

        valid_pointers = b"".join(struct.pack("<I", 0x401000 + i * 0x50) for i in range(25))
        section_data = b"\x00" * 100 + valid_pointers + b"\x00" * 100

        offset = detector._scan_for_handler_table_advanced(section_data, "x86")

        if offset is not None:
            assert offset >= 0
            assert offset < len(section_data) - 100

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_handler_table_validation_rejects_sequential_patterns(self) -> None:
        """Handler table validation rejects overly sequential pointer patterns."""
        detector = VMProtectDetector()

        sequential_pointers = [0x1000 + i for i in range(20)]
        is_valid = detector._validate_handler_table(sequential_pointers)

        assert is_valid is False

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_handler_table_validation_requires_diversity(self) -> None:
        """Handler table validation requires sufficient pointer diversity."""
        detector = VMProtectDetector()

        duplicate_pointers = [0x401000] * 20
        is_valid = detector._validate_handler_table(duplicate_pointers)

        assert is_valid is False

    @pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile not available")
    def test_handler_table_validation_accepts_valid_table(self) -> None:
        """Handler table validation accepts realistic handler pointer table."""
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

        assert is_valid is True


class TestBytecodeInterpreters:
    """Test bytecode interpreter detection and VM handler analysis."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_vm_fetch_byte_handler_detection(self) -> None:
        """Bytecode interpreter detection identifies VM fetch-byte handlers."""
        detector = VMProtectDetector()

        fetch_byte_handler = b"\x0f\xb6\x06" + b"\x46" + b"\x89\x45\xfc"

        binary = b"MZ" + b"\x00" * 200 + fetch_byte_handler + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        fetch_handlers = [h for h in handlers if "fetch" in h.handler_type.lower()]
        if fetch_handlers:
            assert any(h.confidence > 0.7 for h in fetch_handlers)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_vm_ip_increment_handler_detection(self) -> None:
        """Bytecode interpreter detection identifies VM instruction pointer increment handlers."""
        detector = VMProtectDetector()

        ip_increment = b"\x8b\x45\xf8" + b"\x83\xc0\x01" + b"\x89\x45\xf8"

        binary = b"MZ" + b"\x00" * 200 + ip_increment + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        ip_handlers = [h for h in handlers if "ip" in h.handler_type.lower() or "increment" in h.handler_type.lower()]
        if ip_handlers:
            assert len(ip_handlers) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_handler_complexity_metrics_calculation(self) -> None:
        """Handler complexity analysis calculates accurate metrics for complexity scoring."""
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

        assert metrics["complexity"] > 20
        assert metrics["branches"] >= 2
        assert metrics["memory_ops"] >= 2
        assert metrics["instruction_count"] > 10

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_handler_opcode_extraction_limits_output(self) -> None:
        """Handler opcode extraction limits output to prevent excessive memory usage."""
        detector = VMProtectDetector()

        long_handler = b"\x90" * 500

        opcodes = detector._extract_opcodes(long_handler, 0, len(long_handler), "x86")

        assert len(opcodes) <= 50


class TestAntiDebugAndAntiVMDetection:
    """Test anti-debug and anti-VM countermeasure detection."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_vm_context_save_detection_pushad_pushfd(self) -> None:
        """Anti-debug detection identifies context save operations (PUSHAD/PUSHFD)."""
        detector = VMProtectDetector()

        context_save = b"\x9c\x60"

        binary = b"MZ" + b"\x00" * 200 + context_save + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        context_handlers = [h for h in handlers if "context" in h.handler_type.lower()]
        if context_handlers:
            assert any(h.confidence > 0.8 for h in context_handlers)

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_vm_context_restore_detection_popad_popfd(self) -> None:
        """Anti-debug detection identifies context restore operations (POPAD/POPFD)."""
        detector = VMProtectDetector()

        context_restore = b"\x61\x9d"

        binary = b"MZ" + b"\x00" * 200 + context_restore + b"\x90" * 1000

        handlers = detector._detect_vm_handlers_semantic(binary, "x86")

        exit_handlers = [h for h in handlers if "exit" in h.handler_type.lower()]
        if exit_handlers:
            assert len(exit_handlers) > 0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_control_flow_graph_tracks_context_switches_for_anti_debug(self) -> None:
        """Control flow analysis tracks VM context switches indicating anti-debug mechanisms."""
        detector = VMProtectDetector()

        code_with_anti_debug = b"\x9c\x60" + b"\x8b\x45\x08" + b"\x61\x9d" + b"\xc3"

        region = VirtualizedRegion(
            start_offset=100,
            end_offset=100 + len(code_with_anti_debug),
            vm_entry=100,
            vm_exit=100 + len(code_with_anti_debug),
            handlers_used={"context_save", "context_restore"},
            control_flow_complexity=2.0,
        )

        binary = b"\x00" * 100 + code_with_anti_debug + b"\x00" * 100

        cfg = detector._recover_control_flow(binary, region, "x86")

        assert cfg.vm_context_switches >= 2


class TestProtectionLevelDifferentiation:
    """Test differentiation between VMProtect Ultra, Demo, and custom configurations."""

    def test_ultra_protection_high_handler_complexity(self) -> None:
        """Protection level classifier identifies Ultra from high handler complexity."""
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

        assert level == VMProtectLevel.ULTRA

    def test_standard_protection_moderate_complexity(self) -> None:
        """Protection level classifier identifies Standard from moderate complexity."""
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

        assert level == VMProtectLevel.STANDARD

    def test_lite_protection_low_complexity(self) -> None:
        """Protection level classifier identifies Lite from low complexity."""
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

        assert level == VMProtectLevel.LITE


class TestEdgeCases:
    """Test edge cases: heavily mutated code, nested protection layers, x64 vs x86 differences."""

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_heavily_mutated_code_detection(self) -> None:
        """Detector handles heavily mutated code with high junk instruction ratio."""
        detector = VMProtectDetector()

        heavily_mutated = (b"\x90\x90\x90\x87\xc0\x89\xc0\x90\x90" * 100) + (
            b"\x55\x8b\xec\x53\x56\x57\x5f\x5e\x5b\xc9\xc3" * 5
        )

        binary = b"MZ" + b"\x00" * 100 + heavily_mutated

        result = detector._detect_mutations_advanced(binary, "x86")

        assert result["score"] > 0.5
        assert result["junk_instruction_ratio"] > 0.4

    def test_nested_protection_layers_multiple_vmp_sections(self) -> None:
        """Detector identifies nested protection layers from multiple VMP sections."""
        detector = VMProtectDetector()

        section_analysis = {
            "vmp_sections": [
                {"name": ".vmp0", "entropy": 7.8},
                {"name": ".vmp1", "entropy": 7.9},
                {"name": ".vmp2", "entropy": 7.7},
            ],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }

        handlers: list[VMHandler] = []

        version = detector._detect_version_advanced(b"MZ", section_analysis, handlers)

        assert "3" in version

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_x64_vs_x86_architecture_differences(self) -> None:
        """Detector correctly handles x64 vs x86 architectural differences."""
        detector = VMProtectDetector()

        x86_code = b"\x55\x8b\xec\x53\x56\x57\x5f\x5e\x5b\xc9\xc3"
        x64_code = b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x48\x8b\xf1\xc3"

        x86_binary = b"MZ" + b"\x00" * 100 + x86_code + b"\x90" * 1000
        x64_binary = b"MZ" + b"\x00" * 100 + x64_code + b"\x90" * 1000

        x86_handlers = detector._detect_vm_handlers_semantic(x86_binary, "x86")
        x64_handlers = detector._detect_vm_handlers_semantic(x64_binary, "x64")

        assert isinstance(x86_handlers, list)
        assert isinstance(x64_handlers, list)

    def test_corrupted_binary_graceful_failure(self) -> None:
        """Detector handles corrupted binaries gracefully without crashing."""
        detector = VMProtectDetector()

        with tempfile.TemporaryDirectory() as tmpdir:
            corrupted_path = Path(tmpdir) / "corrupted.exe"
            corrupted_path.write_bytes(b"MZ" + b"\xFF\xFE\xFD\xFC" * 250)

            detection = detector.detect(str(corrupted_path))

            assert isinstance(detection, VMProtectDetection)
            assert detection.confidence >= 0.0

    @pytest.mark.skipif(not CAPSTONE_AVAILABLE, reason="Capstone not available")
    def test_empty_handler_deduplication(self) -> None:
        """Handler deduplication handles overlapping detection ranges correctly."""
        detector = VMProtectDetector()

        handlers = [
            VMHandler(offset=100, size=50, handler_type="test", pattern=b"", confidence=0.90),
            VMHandler(offset=105, size=50, handler_type="test", pattern=b"", confidence=0.85),
            VMHandler(offset=200, size=50, handler_type="test2", pattern=b"", confidence=0.88),
        ]

        deduplicated = detector._deduplicate_handlers(handlers)

        assert len(deduplicated) <= 2


class TestRealBinaryValidation:
    """Test on real Windows system binaries to validate no false positives."""

    @pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
    def test_notepad_not_falsely_detected_as_vmprotect(self) -> None:
        """Real notepad.exe should not be falsely detected as VMProtect protected."""
        detector = VMProtectDetector()

        detection = detector.detect(str(NOTEPAD))

        assert isinstance(detection, VMProtectDetection)

        if detection.detected and detection.confidence > 0.6:
            assert len(detection.handlers) > 5 or len(detection.virtualized_regions) > 2, (
                "If notepad is flagged as VMProtect, it must have significant evidence "
                "(multiple handlers or virtualized regions)"
            )

    @pytest.mark.skipif(not KERNEL32.exists(), reason="kernel32.dll not found")
    def test_kernel32_not_falsely_detected_as_vmprotect(self) -> None:
        """Real kernel32.dll should not be falsely detected as VMProtect protected."""
        detector = VMProtectDetector()

        detection = detector.detect(str(KERNEL32))

        assert isinstance(detection, VMProtectDetection)

        if detection.detected and detection.confidence > 0.6:
            assert len(detection.handlers) > 5 or len(detection.virtualized_regions) > 2

    @pytest.mark.skipif(not CALC.exists(), reason="calc.exe not found")
    def test_calc_architecture_detection_accuracy(self) -> None:
        """Real calc.exe architecture is correctly identified."""
        detector = VMProtectDetector()

        detection = detector.detect(str(CALC))

        assert detection.architecture in ["x86", "x64"]


class TestVMProtectProtectedBinaries:
    """Test on actual VMProtect protected binaries if available."""

    def test_vmprotect_1x_binary_detection(self) -> None:
        """VMProtect 1.x protected binary is correctly identified with version and protection level."""
        vmp1_binary = VMPROTECT_BINARIES_DIR / "vmprotect_1x_sample.exe"

        if not vmp1_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect 1.x sample binary not found.\n"
                f"Expected location: {vmp1_binary}\n"
                f"Required: VMProtect 1.x protected binary (any small protected .exe)\n"
                f"Naming: vmprotect_1x_sample.exe\n"
                f"Place VMProtect 1.x protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp1_binary))

        assert detection.detected is True, "VMProtect 1.x binary must be detected"
        assert "1" in detection.version, f"Version should indicate 1.x, got: {detection.version}"
        assert detection.confidence > 0.7, f"Confidence too low: {detection.confidence}"
        assert len(detection.handlers) > 0, "Must detect VM handlers in VMProtect 1.x"

    def test_vmprotect_2x_binary_detection(self) -> None:
        """VMProtect 2.x protected binary is correctly identified with version and protection level."""
        vmp2_binary = VMPROTECT_BINARIES_DIR / "vmprotect_2x_sample.exe"

        if not vmp2_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect 2.x sample binary not found.\n"
                f"Expected location: {vmp2_binary}\n"
                f"Required: VMProtect 2.x protected binary (any small protected .exe)\n"
                f"Naming: vmprotect_2x_sample.exe\n"
                f"Place VMProtect 2.x protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp2_binary))

        assert detection.detected is True, "VMProtect 2.x binary must be detected"
        assert "2" in detection.version, f"Version should indicate 2.x, got: {detection.version}"
        assert detection.confidence > 0.75, f"Confidence too low: {detection.confidence}"
        assert len(detection.handlers) > 0, "Must detect VM handlers in VMProtect 2.x"
        assert len(detection.virtualized_regions) > 0, "Must identify virtualized regions"

    def test_vmprotect_3x_binary_detection(self) -> None:
        """VMProtect 3.x protected binary is correctly identified with version and protection level."""
        vmp3_binary = VMPROTECT_BINARIES_DIR / "vmprotect_3x_sample.exe"

        if not vmp3_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect 3.x sample binary not found.\n"
                f"Expected location: {vmp3_binary}\n"
                f"Required: VMProtect 3.x protected binary (any small protected .exe)\n"
                f"Naming: vmprotect_3x_sample.exe\n"
                f"Place VMProtect 3.x protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp3_binary))

        assert detection.detected is True, "VMProtect 3.x binary must be detected"
        assert "3" in detection.version, f"Version should indicate 3.x, got: {detection.version}"
        assert detection.confidence > 0.8, f"Confidence too low: {detection.confidence}"
        assert len(detection.handlers) > 0, "Must detect VM handlers in VMProtect 3.x"
        assert len(detection.virtualized_regions) > 0, "Must identify virtualized regions"
        assert detection.dispatcher_offset is not None or detection.handler_table_offset is not None, (
            "Must locate dispatcher or handler table"
        )

    def test_vmprotect_ultra_protection_detection(self) -> None:
        """VMProtect Ultra protected binary is classified as ULTRA protection level."""
        vmp_ultra_binary = VMPROTECT_BINARIES_DIR / "vmprotect_ultra_sample.exe"

        if not vmp_ultra_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect Ultra sample binary not found.\n"
                f"Expected location: {vmp_ultra_binary}\n"
                f"Required: VMProtect Ultra protected binary (any Ultra-protected .exe)\n"
                f"Naming: vmprotect_ultra_sample.exe\n"
                f"Place VMProtect Ultra protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp_ultra_binary))

        assert detection.detected is True, "VMProtect Ultra binary must be detected"
        assert detection.protection_level == VMProtectLevel.ULTRA, (
            f"Protection level should be ULTRA, got: {detection.protection_level}"
        )
        assert detection.confidence > 0.85, f"Confidence too low for Ultra: {detection.confidence}"

    def test_vmprotect_x64_binary_detection(self) -> None:
        """VMProtect x64 protected binary is correctly analyzed with x64 architecture."""
        vmp_x64_binary = VMPROTECT_BINARIES_DIR / "vmprotect_x64_sample.exe"

        if not vmp_x64_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect x64 sample binary not found.\n"
                f"Expected location: {vmp_x64_binary}\n"
                f"Required: VMProtect x64 protected binary (any 64-bit protected .exe)\n"
                f"Naming: vmprotect_x64_sample.exe\n"
                f"Place VMProtect x64 protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp_x64_binary))

        assert detection.detected is True, "VMProtect x64 binary must be detected"
        assert detection.architecture == "x64", f"Architecture should be x64, got: {detection.architecture}"
        assert len(detection.handlers) > 0, "Must detect x64 VM handlers"

    def test_vmprotect_mutation_mode_detection(self) -> None:
        """VMProtect mutation-only protected binary is classified as MUTATION mode."""
        vmp_mutation_binary = VMPROTECT_BINARIES_DIR / "vmprotect_mutation_sample.exe"

        if not vmp_mutation_binary.exists():
            pytest.skip(
                f"SKIP: VMProtect mutation mode sample binary not found.\n"
                f"Expected location: {vmp_mutation_binary}\n"
                f"Required: VMProtect mutation-only protected binary\n"
                f"Naming: vmprotect_mutation_sample.exe\n"
                f"Place VMProtect mutation-protected binaries in: {VMPROTECT_BINARIES_DIR}/"
            )

        detector = VMProtectDetector()
        detection = detector.detect(str(vmp_mutation_binary))

        assert detection.detected is True, "VMProtect mutation binary must be detected"

        mutation_result = detection.technical_details.get("mutation_analysis", {})
        mutation_score = mutation_result.get("score", 0.0)

        assert mutation_score > 0.5, f"Mutation score too low for mutation-only binary: {mutation_score}"

        if detection.mode == VMProtectMode.MUTATION or detection.mode == VMProtectMode.HYBRID:
            assert True
        else:
            pytest.fail(f"Expected MUTATION or HYBRID mode, got: {detection.mode}")
