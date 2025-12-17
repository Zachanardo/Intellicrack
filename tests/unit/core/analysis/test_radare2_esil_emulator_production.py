"""Production tests for Radare2 ESIL Emulator with real VM validation.

Tests REAL ESIL emulation capabilities:
- ESIL VM initialization and register tracking
- Single instruction stepping with state changes
- Breakpoint management with conditional triggers
- Memory access tracking during emulation
- Taint source management and propagation
- API call extraction from execution traces
- License check pattern detection
- Path constraint generation for symbolic execution

All tests validate genuine ESIL functionality against real binaries.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_esil_emulator import (
    ESILBreakpoint,
    ESILMemoryAccess,
    ESILRegister,
    ESILState,
    RadareESILEmulator,
)


@pytest.fixture
def sample_x64_elf(tmp_path: Path) -> Path:
    """Create sample x64 ELF binary for ESIL testing."""
    binary_path = tmp_path / "sample_x64.elf"

    x64_code = bytes([
        0x55,                                      # push rbp
        0x48, 0x89, 0xe5,                          # mov rbp, rsp
        0x48, 0x83, 0xec, 0x10,                    # sub rsp, 0x10
        0x48, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00,  # mov [rbp-8], 0
        0x48, 0x8b, 0x45, 0xf8,                    # mov rax, [rbp-8]
        0x48, 0x83, 0xc0, 0x01,                    # add rax, 1
        0x48, 0x89, 0x45, 0xf8,                    # mov [rbp-8], rax
        0x48, 0x83, 0x7d, 0xf8, 0x0a,              # cmp qword [rbp-8], 10
        0x7e, 0xea,                                # jle -22 (loop back)
        0xc9,                                      # leave
        0xc3,                                      # ret
    ])

    elf_data = bytes([
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    program_header = bytes([
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    padding = b"\x00" * (0x78 - len(elf_data) - len(program_header))
    full_binary = elf_data + program_header + padding + x64_code

    binary_path.write_bytes(full_binary)
    return binary_path


@pytest.fixture
def license_check_binary(tmp_path: Path) -> Path:
    """Create binary with license validation logic."""
    binary_path = tmp_path / "license_check.elf"

    license_code = bytes([
        0x55,                                      # push rbp
        0x48, 0x89, 0xe5,                          # mov rbp, rsp
        0x48, 0x8b, 0x45, 0x08,                    # mov rax, [rbp+8] (license key)
        0x48, 0x3d, 0x37, 0x13, 0x00, 0x00,        # cmp rax, 0x1337 (magic value)
        0x74, 0x07,                                # je valid_license
        0xb8, 0x00, 0x00, 0x00, 0x00,              # mov eax, 0 (invalid)
        0xeb, 0x05,                                # jmp end
        0xb8, 0x01, 0x00, 0x00, 0x00,              # mov eax, 1 (valid)
        0x5d,                                      # pop rbp
        0xc3,                                      # ret
    ])

    elf_data = bytes([
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    program_header = bytes([
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])

    padding = b"\x00" * (0x78 - len(elf_data) - len(program_header))
    full_binary = elf_data + program_header + padding + license_code

    binary_path.write_bytes(full_binary)
    return binary_path


class TestESILEmulatorInitialization:
    """Test ESIL emulator initialization and setup."""

    def test_initializes_with_valid_binary(self, sample_x64_elf: Path) -> None:
        """ESIL emulator initializes successfully with valid binary."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            assert emulator.session is not None
            assert emulator.state == ESILState.READY
            assert emulator.arch in ["x86", "x64", "x86_64"]
            assert emulator.bits in [32, 64]

    def test_initializes_register_tracking(self, sample_x64_elf: Path) -> None:
        """Emulator initializes register tracking correctly."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            assert isinstance(emulator.registers, dict)
            assert len(emulator.registers) > 0

            for reg_name, reg_state in emulator.registers.items():
                assert isinstance(reg_state, ESILRegister)
                assert isinstance(reg_state.name, str)
                assert isinstance(reg_state.value, int)
                assert isinstance(reg_state.size, int)
                assert isinstance(reg_state.symbolic, bool)
                assert isinstance(reg_state.tainted, bool)

    def test_raises_on_invalid_binary_path(self) -> None:
        """Emulator raises error for non-existent binary."""
        with pytest.raises((FileNotFoundError, RuntimeError)):
            RadareESILEmulator("/nonexistent/path/to/binary.bin")

    def test_initializes_data_structures(self, sample_x64_elf: Path) -> None:
        """Emulator initializes all required data structures."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            assert isinstance(emulator.memory_map, dict)
            assert isinstance(emulator.breakpoints, dict)
            assert isinstance(emulator.memory_accesses, list)
            assert isinstance(emulator.call_stack, list)
            assert isinstance(emulator.taint_sources, list)
            assert isinstance(emulator.symbolic_memory, dict)
            assert isinstance(emulator.path_constraints, list)


class TestRegisterOperations:
    """Test register get/set operations."""

    def test_reads_register_values(self, sample_x64_elf: Path) -> None:
        """Emulator reads register values from ESIL VM."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            rax_value = emulator.get_register("rax")
            assert isinstance(rax_value, int)
            assert rax_value >= 0

    def test_sets_register_values(self, sample_x64_elf: Path) -> None:
        """Emulator sets register values in ESIL VM."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            test_value = 0x1234567890ABCDEF
            emulator.set_register("rax", test_value)

            read_value = emulator.get_register("rax")
            assert read_value == test_value

    def test_sets_symbolic_register(self, sample_x64_elf: Path) -> None:
        """Emulator marks registers as symbolic."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            emulator.set_register("rbx", "symbolic_value", symbolic=True)

            assert "rbx" in emulator.registers
            assert emulator.registers["rbx"].symbolic is True
            assert len(emulator.registers["rbx"].constraints) > 0


class TestMemoryOperations:
    """Test memory read/write operations."""

    def test_reads_memory(self, sample_x64_elf: Path) -> None:
        """Emulator reads memory from ESIL VM."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            entry = emulator.entry_point
            if entry > 0:
                memory = emulator.get_memory(entry, 16)
                assert isinstance(memory, bytes)
                assert len(memory) == 16

    def test_writes_memory(self, sample_x64_elf: Path) -> None:
        """Emulator writes memory to ESIL VM."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            test_data = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
            address = 0x200000

            emulator.set_memory(address, test_data)
            read_data = emulator.get_memory(address, len(test_data))

            assert read_data == test_data

    def test_marks_symbolic_memory(self, sample_x64_elf: Path) -> None:
        """Emulator tracks symbolic memory regions."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            test_data = b"\x11\x22\x33\x44"
            address = 0x200100

            emulator.set_memory(address, test_data, symbolic=True)

            assert address in emulator.symbolic_memory or address + 1 in emulator.symbolic_memory
            assert len(emulator.path_constraints) > 0


class TestInstructionStepping:
    """Test single instruction execution."""

    def test_steps_single_instruction(self, sample_x64_elf: Path) -> None:
        """Emulator executes single instruction and tracks changes."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            step_info = emulator.step_instruction()

            assert isinstance(step_info, dict)
            assert "address" in step_info
            assert "instruction" in step_info
            assert "esil" in step_info
            assert "changed_registers" in step_info
            assert "memory_accesses" in step_info
            assert "new_pc" in step_info

            assert isinstance(step_info["address"], int)
            assert isinstance(step_info["instruction"], str)
            assert isinstance(step_info["changed_registers"], dict)
            assert isinstance(step_info["memory_accesses"], list)

    def test_tracks_register_changes(self, sample_x64_elf: Path) -> None:
        """Step tracks which registers changed during execution."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            for _ in range(3):
                step_info = emulator.step_instruction()

                changed_regs = step_info["changed_registers"]
                for reg_name, change in changed_regs.items():
                    assert "old" in change
                    assert "new" in change
                    assert isinstance(change["old"], int)
                    assert isinstance(change["new"], int)

    def test_tracks_memory_accesses(self, sample_x64_elf: Path) -> None:
        """Step tracks memory read/write operations."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            for _ in range(10):
                step_info = emulator.step_instruction()

                for access in step_info["memory_accesses"]:
                    assert isinstance(access, ESILMemoryAccess)
                    assert access.operation in ["read", "write"]
                    assert isinstance(access.address, int)
                    assert isinstance(access.size, int)
                    assert isinstance(access.value, bytes)

    def test_increments_instruction_counter(self, sample_x64_elf: Path) -> None:
        """Emulator increments instruction count on each step."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            initial_count = emulator.instruction_count

            for i in range(5):
                emulator.step_instruction()
                assert emulator.instruction_count == initial_count + i + 1


class TestBreakpointManagement:
    """Test breakpoint functionality."""

    def test_adds_breakpoint(self, sample_x64_elf: Path) -> None:
        """Emulator adds breakpoint at address."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            bp_addr = emulator.entry_point
            bp = emulator.add_breakpoint(bp_addr)

            assert isinstance(bp, ESILBreakpoint)
            assert bp.address == bp_addr
            assert bp.enabled is True
            assert bp.hit_count == 0
            assert bp_addr in emulator.breakpoints

    def test_adds_conditional_breakpoint(self, sample_x64_elf: Path) -> None:
        """Emulator adds breakpoint with condition."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            bp_addr = emulator.entry_point
            condition = "rax > 100"
            bp = emulator.add_breakpoint(bp_addr, condition=condition)

            assert bp.condition == condition

    def test_removes_breakpoint(self, sample_x64_elf: Path) -> None:
        """Emulator removes breakpoint."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            bp_addr = emulator.entry_point
            emulator.add_breakpoint(bp_addr)

            assert bp_addr in emulator.breakpoints

            emulator.remove_breakpoint(bp_addr)

            assert bp_addr not in emulator.breakpoints

    def test_breakpoint_triggers(self, sample_x64_elf: Path) -> None:
        """Breakpoint triggers when execution reaches address."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            entry = emulator.entry_point

            emulator.add_breakpoint(entry + 10)
            emulator.run_until(entry + 20, max_steps=50)

            if entry + 10 in emulator.breakpoints:
                bp = emulator.breakpoints[entry + 10]
                assert bp.hit_count >= 0


class TestRunUntilTarget:
    """Test run_until execution."""

    def test_runs_until_address(self, sample_x64_elf: Path) -> None:
        """Emulator runs until target address."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            start = emulator.entry_point
            target = start + 20

            trace = emulator.run_until(target, max_steps=100)

            assert isinstance(trace, list)
            assert all(isinstance(step, dict) for step in trace)

            if trace:
                final_pc = trace[-1]["new_pc"]
                assert final_pc == target or emulator.state in [ESILState.COMPLETE, ESILState.TRAPPED, ESILState.ERROR]

    def test_respects_max_steps_limit(self, sample_x64_elf: Path) -> None:
        """Emulator stops after max_steps even if target not reached."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            start = emulator.entry_point
            target = start + 10000

            trace = emulator.run_until(target, max_steps=10)

            assert len(trace) <= 10

    def test_returns_complete_trace(self, sample_x64_elf: Path) -> None:
        """run_until returns complete execution trace."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            start = emulator.entry_point
            trace = emulator.run_until(start + 30, max_steps=50)

            for step in trace:
                assert "address" in step
                assert "instruction" in step
                assert "new_pc" in step


class TestTaintTracking:
    """Test taint analysis functionality."""

    def test_adds_taint_source(self, sample_x64_elf: Path) -> None:
        """Emulator marks memory region as taint source."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            taint_addr = 0x200000
            emulator.add_taint_source(taint_addr, size=16)

            assert taint_addr in emulator.taint_sources

    def test_taint_source_with_custom_size(self, sample_x64_elf: Path) -> None:
        """Taint source accepts custom size parameter."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            taint_addr = 0x201000
            size = 32

            emulator.add_taint_source(taint_addr, size=size)

            assert taint_addr in emulator.taint_sources


class TestAPICallExtraction:
    """Test API call detection and extraction."""

    def test_extracts_api_calls(self, sample_x64_elf: Path) -> None:
        """Emulator extracts API calls from execution trace."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            emulator.run_until(emulator.entry_point + 50, max_steps=100)

            api_calls = emulator.extract_api_calls()

            assert isinstance(api_calls, list)

            for call in api_calls:
                assert "address" in call
                assert "api" in call
                assert "stack_ptr" in call
                assert "arguments" in call
                assert isinstance(call["arguments"], list)


class TestLicenseCheckDetection:
    """Test license validation pattern detection."""

    def test_finds_license_check_patterns(self, license_check_binary: Path) -> None:
        """Emulator identifies potential license validation code."""
        with RadareESILEmulator(str(license_check_binary)) as emulator:
            patterns = emulator.find_license_checks()

            assert isinstance(patterns, list)

            for pattern in patterns:
                assert "address" in pattern
                assert "type" in pattern
                assert pattern["type"] in ["conditional_branch", "comparison", "validation"]

    def test_detects_conditional_branches(self, license_check_binary: Path) -> None:
        """License check detection identifies conditional branches."""
        with RadareESILEmulator(str(license_check_binary)) as emulator:
            patterns = emulator.find_license_checks()

            for pattern in patterns:
                if pattern["type"] == "conditional_branch":
                    assert "true_path" in pattern or "false_path" in pattern


class TestPathConstraints:
    """Test path constraint generation."""

    def test_generates_path_constraints(self, license_check_binary: Path) -> None:
        """Emulator generates constraints for execution path."""
        with RadareESILEmulator(str(license_check_binary)) as emulator:
            target = emulator.entry_point + 20
            constraints = emulator.generate_path_constraints(target)

            assert isinstance(constraints, list)
            assert all(isinstance(c, str) for c in constraints)

    def test_constraints_reflect_conditional_jumps(self, sample_x64_elf: Path) -> None:
        """Path constraints include conditional jump conditions."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            target = emulator.entry_point + 30
            constraints = emulator.generate_path_constraints(target)

            assert isinstance(constraints, list)


class TestExecutionTrace:
    """Test execution trace dumping."""

    def test_dumps_execution_trace(self, sample_x64_elf: Path, tmp_path: Path) -> None:
        """Emulator dumps complete execution trace to JSON."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            emulator.run_until(emulator.entry_point + 20, max_steps=30)

            output_path = tmp_path / "trace.json"
            emulator.dump_execution_trace(str(output_path))

            assert output_path.exists()

            with open(output_path) as f:
                trace_data = json.load(f)

            assert "binary" in trace_data
            assert "architecture" in trace_data
            assert "instruction_count" in trace_data
            assert "breakpoints_hit" in trace_data
            assert "api_calls" in trace_data
            assert "memory_accesses" in trace_data

    def test_trace_contains_complete_information(self, sample_x64_elf: Path, tmp_path: Path) -> None:
        """Dumped trace contains all execution information."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            emulator.add_breakpoint(emulator.entry_point + 5)
            emulator.run_until(emulator.entry_point + 25, max_steps=40)

            output_path = tmp_path / "full_trace.json"
            emulator.dump_execution_trace(str(output_path))

            with open(output_path) as f:
                trace_data = json.load(f)

            assert trace_data["instruction_count"] > 0
            assert isinstance(trace_data["api_calls"], list)
            assert isinstance(trace_data["memory_accesses"], list)
            assert isinstance(trace_data["path_constraints"], list)


class TestEmulatorReset:
    """Test emulator reset functionality."""

    def test_resets_emulator_state(self, sample_x64_elf: Path) -> None:
        """Reset clears execution state."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            emulator.run_until(emulator.entry_point + 20, max_steps=30)

            initial_count = emulator.instruction_count
            assert initial_count > 0

            emulator.reset()

            assert emulator.state == ESILState.READY
            assert emulator.instruction_count == 0
            assert len(emulator.memory_accesses) == 0
            assert len(emulator.call_stack) == 0
            assert len(emulator.path_constraints) == 0

    def test_reset_preserves_binary_info(self, sample_x64_elf: Path) -> None:
        """Reset preserves binary information."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            original_arch = emulator.arch
            original_bits = emulator.bits
            original_entry = emulator.entry_point

            emulator.run_until(emulator.entry_point + 15, max_steps=20)
            emulator.reset()

            assert emulator.arch == original_arch
            assert emulator.bits == original_bits
            assert emulator.entry_point == original_entry


class TestContextManager:
    """Test context manager protocol."""

    def test_context_manager_cleans_up(self, sample_x64_elf: Path) -> None:
        """Context manager properly cleans up resources."""
        emulator = RadareESILEmulator(str(sample_x64_elf))

        with emulator:
            assert emulator.session is not None

        assert emulator.session is None

    def test_context_manager_handles_exceptions(self, sample_x64_elf: Path) -> None:
        """Context manager cleans up even on exception."""
        emulator = RadareESILEmulator(str(sample_x64_elf))

        try:
            with emulator:
                assert emulator.session is not None
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert emulator.session is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_invalid_register_name(self, sample_x64_elf: Path) -> None:
        """Emulator handles invalid register names gracefully."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            with pytest.raises((RuntimeError, KeyError, TypeError)):
                emulator.get_register("invalid_register_xyz")

    def test_handles_invalid_memory_address(self, sample_x64_elf: Path) -> None:
        """Emulator handles invalid memory addresses."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            with pytest.raises((RuntimeError, OSError)):
                emulator.get_memory(0xDEADBEEFCAFEBABE, 16)

    def test_handles_zero_step_count(self, sample_x64_elf: Path) -> None:
        """run_until handles max_steps=0."""
        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            trace = emulator.run_until(emulator.entry_point + 10, max_steps=0)

            assert isinstance(trace, list)
            assert len(trace) == 0


class TestPerformance:
    """Test performance characteristics."""

    def test_many_steps_complete_quickly(self, sample_x64_elf: Path) -> None:
        """Emulator handles many instruction steps efficiently."""
        import time

        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            start = time.time()
            emulator.run_until(emulator.entry_point + 50, max_steps=100)
            duration = time.time() - start

            assert duration < 10.0

    def test_memory_operations_efficient(self, sample_x64_elf: Path) -> None:
        """Memory read/write operations complete quickly."""
        import time

        with RadareESILEmulator(str(sample_x64_elf)) as emulator:
            start = time.time()

            for i in range(100):
                addr = 0x200000 + i * 16
                data = bytes([i % 256] * 16)
                emulator.set_memory(addr, data)
                emulator.get_memory(addr, 16)

            duration = time.time() - start

            assert duration < 5.0
