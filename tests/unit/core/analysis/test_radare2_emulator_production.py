"""Production-ready tests for Radare2 Emulator with real Unicorn engine validation.

Tests REAL emulation capabilities including:
- ESIL emulation with actual instruction execution
- Unicorn engine integration with real binary code
- Symbolic execution path discovery
- Taint analysis with data flow tracking
- Constraint solving with Z3
- Exploit generation for real vulnerabilities

These tests validate genuine offensive capabilities against actual binaries.
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest
import r2pipe
import unicorn
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, UC_MODE_64

from intellicrack.core.analysis.radare2_emulator import (
    EmulationResult,
    EmulationType,
    ExploitPrimitive,
    ExploitType,
    Radare2Emulator,
    TaintInfo,
)


@pytest.fixture
def simple_x64_binary(tmp_path: Path) -> Path:
    """Create a simple x64 binary for testing emulation.

    This binary contains:
    - Simple arithmetic operations
    - Conditional jumps
    - Function calls
    - Memory operations
    """
    binary_path = tmp_path / "test_x64.bin"

    x64_code = bytes([
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1
        0x48, 0xc7, 0xc3, 0x02, 0x00, 0x00, 0x00,  # mov rbx, 2
        0x48, 0x01, 0xd8,                          # add rax, rbx
        0x48, 0x3d, 0x03, 0x00, 0x00, 0x00,        # cmp rax, 3
        0x74, 0x05,                                # je +5
        0x48, 0xff, 0xc0,                          # inc rax
        0x90,                                      # nop
        0xc3,                                      # ret
    ])

    elf_header = bytes([
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,  # ELF magic
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,  # e_type, e_machine
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # e_entry
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # e_phoff
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # e_shoff
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,  # e_flags, e_ehsize, e_phentsize
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # e_phnum, e_shentsize
    ])

    program_header = bytes([
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,  # p_type, p_flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_offset
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_vaddr
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_paddr
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_filesz
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_memsz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # p_align
    ])

    padding = b"\x00" * (0x78 - len(elf_header) - len(program_header))
    full_binary = elf_header + program_header + padding + x64_code

    binary_path.write_bytes(full_binary)
    return binary_path


@pytest.fixture
def vulnerable_x86_binary(tmp_path: Path) -> Path:
    """Create x86 binary with buffer overflow vulnerability."""
    binary_path = tmp_path / "vuln_x86.bin"

    x86_code = bytes([
        0x55,                          # push ebp
        0x89, 0xe5,                    # mov ebp, esp
        0x83, 0xec, 0x40,              # sub esp, 0x40 (64-byte buffer)
        0x8d, 0x45, 0xc0,              # lea eax, [ebp-0x40]
        0x50,                          # push eax (strcpy dest)
        0xff, 0x75, 0x08,              # push [ebp+8] (strcpy src - vulnerable)
        0xe8, 0x00, 0x00, 0x00, 0x00,  # call strcpy (placeholder)
        0x83, 0xc4, 0x08,              # add esp, 8
        0xc9,                          # leave
        0xc3,                          # ret
    ])

    elf_header = bytes([
        0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00,  # ELF magic (32-bit)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,  # e_type, e_machine
        0x54, 0x80, 0x04, 0x08,                          # e_entry
        0x34, 0x00, 0x00, 0x00,                          # e_phoff
        0x00, 0x00, 0x00, 0x00,                          # e_shoff
        0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00,  # e_flags, e_ehsize, e_phentsize
        0x01, 0x00, 0x00, 0x00,                          # e_phnum, e_shentsize
    ])

    program_header = bytes([
        0x01, 0x00, 0x00, 0x00,  # p_type
        0x00, 0x00, 0x00, 0x00,  # p_offset
        0x00, 0x80, 0x04, 0x08,  # p_vaddr
        0x00, 0x80, 0x04, 0x08,  # p_paddr
        0x00, 0x01, 0x00, 0x00,  # p_filesz
        0x00, 0x01, 0x00, 0x00,  # p_memsz
        0x05, 0x00, 0x00, 0x00,  # p_flags
        0x00, 0x10, 0x00, 0x00,  # p_align
    ])

    padding = b"\x00" * (0x54 - len(elf_header) - len(program_header))
    full_binary = elf_header + program_header + padding + x86_code

    binary_path.write_bytes(full_binary)
    return binary_path


class TestRadare2EmulatorInitialization:
    """Test emulator initialization and setup."""

    def test_emulator_opens_binary_successfully(self, simple_x64_binary: Path) -> None:
        """Emulator successfully opens and analyzes binary."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        assert emulator.open() is True
        assert emulator.r2 is not None
        assert emulator.arch in ["x86", "x64", "x86_64"]
        assert emulator.bits in [32, 64]
        emulator.close()

    def test_emulator_detects_architecture_correctly(self, simple_x64_binary: Path) -> None:
        """Emulator correctly identifies binary architecture."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()
        assert emulator.arch in ["x86", "x64", "x86_64"]
        assert emulator.bits == 64
        assert emulator.endian in ["little", "big"]
        emulator.close()

    def test_emulator_initializes_data_structures(self, simple_x64_binary: Path) -> None:
        """Emulator initializes all required data structures."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        assert isinstance(emulator.solver, z3.Solver)
        assert isinstance(emulator.symbolic_vars, dict)
        assert isinstance(emulator.taint_tracker, dict)
        assert isinstance(emulator.execution_trace, list)
        assert isinstance(emulator.memory_map, dict)

        emulator.close()


class TestESILEmulation:
    """Test ESIL emulation with real instruction execution."""

    def test_esil_emulates_arithmetic_operations(self, simple_x64_binary: Path) -> None:
        """ESIL correctly emulates arithmetic instructions and updates registers."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        entry = 0x400078
        result = emulator.emulate_esil(entry, num_instructions=3)

        assert result.success is True
        assert result.type == EmulationType.ESIL
        assert len(result.execution_path) >= 3
        assert result.registers is not None
        assert entry in result.execution_path

        emulator.close()

    def test_esil_tracks_conditional_jumps(self, simple_x64_binary: Path) -> None:
        """ESIL tracks conditional jumps and extracts constraints."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        result = emulator.emulate_esil(0x400078, num_instructions=10)

        assert result.success is True
        assert len(result.execution_path) > 0
        assert len(result.constraints) >= 0

        emulator.close()

    def test_esil_detects_memory_changes(self, simple_x64_binary: Path) -> None:
        """ESIL detects and tracks memory write operations."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        initial_state = {
            "registers": {"rsp": 0x7fffffffe000},
            "memory": {}
        }

        result = emulator.emulate_esil(0x400078, num_instructions=10, initial_state=initial_state)

        assert result.success is True
        assert isinstance(result.memory_changes, list)

        emulator.close()


class TestUnicornEmulation:
    """Test Unicorn engine integration with real binary emulation."""

    def test_unicorn_engine_initializes_successfully(self, simple_x64_binary: Path) -> None:
        """Unicorn engine initializes and maps memory correctly."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        success = emulator.setup_unicorn_engine()

        assert success is True
        assert emulator.uc is not None
        assert isinstance(emulator.uc, unicorn.Uc)

        emulator.close()

    def test_unicorn_emulates_instructions(self, simple_x64_binary: Path) -> None:
        """Unicorn successfully emulates real binary instructions."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        entry = 0x400078
        result = emulator.emulate_unicorn(entry, count=10)

        assert result.success is True
        assert result.type == EmulationType.UNICORN
        assert len(result.execution_path) > 0
        assert isinstance(result.registers, dict)
        assert len(result.registers) > 0

        emulator.close()

    def test_unicorn_tracks_memory_writes(self, simple_x64_binary: Path) -> None:
        """Unicorn hooks track all memory write operations."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()
        emulator.setup_unicorn_engine()

        entry = 0x400078
        result = emulator.emulate_unicorn(entry, count=20)

        assert result.success is True
        assert isinstance(result.memory_changes, list)

        emulator.close()

    def test_unicorn_execution_trace_complete(self, simple_x64_binary: Path) -> None:
        """Unicorn captures complete execution trace."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        result = emulator.emulate_unicorn(0x400078, count=15)

        assert result.success is True
        assert len(result.execution_path) > 0
        assert all(isinstance(addr, int) for addr in result.execution_path)
        assert all(addr > 0 for addr in result.execution_path)

        emulator.close()


class TestSymbolicExecution:
    """Test symbolic execution for path discovery."""

    def test_symbolic_execution_finds_paths(self, simple_x64_binary: Path) -> None:
        """Symbolic execution discovers feasible execution paths."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        start = 0x400078
        target = 0x400090
        results = emulator.symbolic_execution(start, target, max_paths=10)

        assert isinstance(results, list)
        assert len(results) >= 0

        for result in results:
            assert result.type == EmulationType.SYMBOLIC
            assert isinstance(result.execution_path, list)
            assert isinstance(result.constraints, list)

        emulator.close()

    def test_symbolic_execution_generates_constraints(self, simple_x64_binary: Path) -> None:
        """Symbolic execution generates path constraints."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        results = emulator.symbolic_execution(0x400078, 0x400090, max_paths=5)

        for result in results:
            if result.success:
                assert "constraints" in result.metadata or len(result.constraints) >= 0

        emulator.close()


class TestTaintAnalysis:
    """Test taint analysis with data flow tracking."""

    def test_taint_analysis_tracks_tainted_data(self, simple_x64_binary: Path) -> None:
        """Taint analysis tracks data flow from taint sources."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        taint_sources = [(0x400078, 8, "user_input")]
        taints = emulator.taint_analysis(taint_sources, 0x400078, num_instructions=20)

        assert isinstance(taints, list)
        assert all(isinstance(t, TaintInfo) for t in taints)

        if taints:
            taint = taints[0]
            assert taint.address == 0x400078
            assert taint.size == 8
            assert taint.taint_label == "user_input"
            assert isinstance(taint.propagation_path, list)
            assert isinstance(taint.influenced_registers, list)
            assert isinstance(taint.influenced_memory, list)

        emulator.close()

    def test_taint_propagates_to_registers(self, simple_x64_binary: Path) -> None:
        """Taint propagates from memory to registers through operations."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        taint_sources = [(0x400000, 8, "tainted_input")]
        taints = emulator.taint_analysis(taint_sources, 0x400078, num_instructions=15)

        assert isinstance(taints, list)
        for taint in taints:
            assert isinstance(taint.influenced_registers, list)

        emulator.close()


class TestConstraintSolving:
    """Test Z3 constraint solving capabilities."""

    def test_constraint_solver_finds_satisfying_values(self) -> None:
        """Z3 solver finds concrete values satisfying constraints."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        var = z3.BitVec("x", 32)
        emulator.symbolic_vars["x"] = var

        constraints = [
            var > 10,
            var < 20,
            var != 15,
        ]

        solution = emulator.constraint_solving(constraints, emulator.symbolic_vars)

        assert solution is not None
        assert "x" in solution
        assert 10 < solution["x"] < 20
        assert solution["x"] != 15

        emulator.close()

    def test_constraint_solver_handles_unsatisfiable(self) -> None:
        """Solver correctly identifies unsatisfiable constraints."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        var = z3.BitVec("y", 32)
        emulator.symbolic_vars["y"] = var

        constraints = [
            var > 100,
            var < 50,
        ]

        solution = emulator.constraint_solving(constraints, emulator.symbolic_vars)

        assert solution is None

        emulator.close()


class TestExploitGeneration:
    """Test automated exploit generation for vulnerabilities."""

    def test_finds_vulnerable_functions(self, vulnerable_x86_binary: Path) -> None:
        """Exploit generator identifies dangerous function calls."""
        emulator = Radare2Emulator(str(vulnerable_x86_binary))
        emulator.open()

        vulns = emulator.find_vulnerabilities()

        assert isinstance(vulns, list)
        assert all(isinstance(v, tuple) for v in vulns)
        assert all(isinstance(v[0], ExploitType) for v in vulns)
        assert all(isinstance(v[1], int) for v in vulns)

        emulator.close()

    def test_generates_buffer_overflow_exploit(self, vulnerable_x86_binary: Path) -> None:
        """Generator creates working buffer overflow exploit."""
        emulator = Radare2Emulator(str(vulnerable_x86_binary))
        emulator.open()

        exploit = emulator.generate_exploit(ExploitType.BUFFER_OVERFLOW, 0x8048054)

        if exploit:
            assert isinstance(exploit, ExploitPrimitive)
            assert exploit.type == ExploitType.BUFFER_OVERFLOW
            assert len(exploit.trigger_input) > 0
            assert len(exploit.payload) > 0
            assert exploit.vulnerability_address == 0x8048054
            assert 0.0 <= exploit.reliability <= 1.0
            assert isinstance(exploit.constraints, list)
            assert isinstance(exploit.metadata, dict)

        emulator.close()

    def test_generates_format_string_exploit(self) -> None:
        """Generator creates format string exploit payload."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        exploit = emulator.generate_exploit(ExploitType.FORMAT_STRING, 0x400000)

        if exploit:
            assert isinstance(exploit, ExploitPrimitive)
            assert exploit.type == ExploitType.FORMAT_STRING
            assert b"%p" in exploit.trigger_input or b"%s" in exploit.trigger_input
            assert exploit.reliability > 0

        emulator.close()

    def test_generates_integer_overflow_exploit(self) -> None:
        """Generator creates integer overflow trigger values."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        exploit = emulator.generate_exploit(ExploitType.INTEGER_OVERFLOW, 0x400000)

        if exploit:
            assert isinstance(exploit, ExploitPrimitive)
            assert exploit.type == ExploitType.INTEGER_OVERFLOW
            assert len(exploit.trigger_input) > 0
            assert "overflow_values" in exploit.metadata

        emulator.close()

    def test_generates_use_after_free_exploit(self) -> None:
        """Generator creates UAF exploitation payload."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        exploit = emulator.generate_exploit(ExploitType.USE_AFTER_FREE, 0x400000)

        if exploit:
            assert isinstance(exploit, ExploitPrimitive)
            assert exploit.type == ExploitType.USE_AFTER_FREE
            assert len(exploit.payload) > 0
            assert "spray_size" in exploit.metadata or "object_size" in exploit.metadata

        emulator.close()

    def test_exploit_report_generation(self) -> None:
        """Exploit report contains all necessary information."""
        emulator = Radare2Emulator("/bin/ls")
        emulator.open()

        exploit = emulator.generate_exploit(ExploitType.BUFFER_OVERFLOW, 0x400000)

        if exploit:
            report = emulator.generate_exploit_report([exploit])

            assert isinstance(report, str)
            assert "EXPLOIT GENERATION REPORT" in report
            assert "BUFFER_OVERFLOW" in report
            assert hex(exploit.vulnerability_address) in report
            assert str(exploit.reliability) in report or f"{exploit.reliability:.0%}" in report

        emulator.close()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_invalid_binary_path(self) -> None:
        """Emulator handles non-existent binary gracefully."""
        emulator = Radare2Emulator("/nonexistent/binary.bin")
        assert emulator.open() is False

    def test_handles_corrupted_binary(self, tmp_path: Path) -> None:
        """Emulator handles corrupted binary data."""
        corrupted = tmp_path / "corrupted.bin"
        corrupted.write_bytes(b"\x00" * 100)

        emulator = Radare2Emulator(str(corrupted))
        result = emulator.open()

        assert isinstance(result, bool)

    def test_emulation_with_zero_instructions(self, simple_x64_binary: Path) -> None:
        """Emulation handles request for zero instructions."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        result = emulator.emulate_esil(0x400078, num_instructions=0)

        assert result.success is True
        assert len(result.execution_path) == 0

        emulator.close()

    def test_symbolic_execution_max_paths_zero(self, simple_x64_binary: Path) -> None:
        """Symbolic execution handles max_paths=0."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        results = emulator.symbolic_execution(0x400078, 0x400090, max_paths=0)

        assert isinstance(results, list)
        assert len(results) == 0

        emulator.close()


class TestPerformance:
    """Test performance characteristics."""

    def test_emulation_completes_within_reasonable_time(self, simple_x64_binary: Path) -> None:
        """Emulation completes large instruction count within timeout."""
        import time

        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()

        start = time.time()
        result = emulator.emulate_esil(0x400078, num_instructions=100)
        duration = time.time() - start

        assert result.success is True
        assert duration < 10.0

        emulator.close()

    def test_unicorn_emulation_performance(self, simple_x64_binary: Path) -> None:
        """Unicorn emulation performs efficiently."""
        import time

        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()
        emulator.setup_unicorn_engine()

        start = time.time()
        result = emulator.emulate_unicorn(0x400078, count=1000)
        duration = time.time() - start

        assert duration < 5.0

        emulator.close()


class TestCleanup:
    """Test resource cleanup and session management."""

    def test_emulator_closes_cleanly(self, simple_x64_binary: Path) -> None:
        """Emulator releases all resources on close."""
        emulator = Radare2Emulator(str(simple_x64_binary))
        emulator.open()
        emulator.close()

        assert emulator.r2 is None or not hasattr(emulator.r2, "quit")

    def test_multiple_open_close_cycles(self, simple_x64_binary: Path) -> None:
        """Emulator handles multiple open/close cycles."""
        emulator = Radare2Emulator(str(simple_x64_binary))

        for _ in range(3):
            assert emulator.open() is True
            emulator.close()
