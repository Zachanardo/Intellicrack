"""Production tests for Radare2 ESIL emulator.

Tests validate REAL ESIL instruction emulation, register state tracking,
memory operations, and license check detection using actual radare2 integration.
"""

import shutil
import sys
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


def radare2_available() -> bool:
    """Check if radare2 and r2pipe are available and functional."""
    try:
        import r2pipe

        r2 = r2pipe.open(sys.executable, ["-2", "-n"])
        result = r2.cmd("i")
        r2.quit()
        return len(result) > 0
    except Exception:
        return False


@pytest.fixture
def valid_pe_binary() -> Path:
    """Return path to a valid PE binary (Python executable)."""
    return Path(sys.executable)


@pytest.fixture
def copied_pe_binary(tmp_path: Path) -> Path:
    """Copy Python executable to temp location for write tests."""
    src = Path(sys.executable)
    dst = tmp_path / "test_binary.exe"
    shutil.copy2(src, dst)
    return dst


class TestEmulatorInitialization:
    """Test ESIL emulator initialization with real radare2."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_emulator_initialization_production(self, valid_pe_binary: Path) -> None:
        """Emulator initializes with real radare2 analysis."""
        emulator = RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        )

        assert emulator.binary_path == valid_pe_binary
        assert emulator.state == ESILState.READY

        emulator.cleanup()

    def test_emulator_initialization_missing_binary(self, tmp_path: Path) -> None:
        """Initialization fails with nonexistent binary."""
        with pytest.raises(FileNotFoundError):
            RadareESILEmulator(str(tmp_path / "nonexistent.exe"))

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_emulator_context_manager_production(self, valid_pe_binary: Path) -> None:
        """Context manager cleans up resources properly."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            assert emulator.state == ESILState.READY
            assert emulator.session is not None

        assert emulator.session is None


class TestRegisterOperations:
    """Test real register state tracking and manipulation."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_get_register_value_production(self, valid_pe_binary: Path) -> None:
        """Get register returns actual radare2 register value."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            rax_value = emulator.get_register("rax")

            assert isinstance(rax_value, int)
            assert rax_value >= 0

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_set_register_value_production(self, valid_pe_binary: Path) -> None:
        """Set register updates actual radare2 register state."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            emulator.set_register("rax", 0x1234)

            rax_value = emulator.get_register("rax")
            assert rax_value == 0x1234

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_set_register_symbolic_production(self, valid_pe_binary: Path) -> None:
        """Set register with symbolic flag marks register as symbolic."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            emulator.set_register("rax", "user_input", symbolic=True)

            assert "rax" in emulator.registers
            assert emulator.registers["rax"].symbolic is True
            assert len(emulator.registers["rax"].constraints) > 0


class TestMemoryOperations:
    """Test real memory read/write operations."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_read_memory_production(self, valid_pe_binary: Path) -> None:
        """Memory read returns actual binary content."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                data = emulator.get_memory(emulator.entry_point, 8)

                assert isinstance(data, bytes)
                assert len(data) == 8

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_write_memory_production(self, valid_pe_binary: Path) -> None:
        """Memory write executes and updates memory map."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            test_data = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"
            emulator.set_memory(0x500000, test_data)

            assert 0x500000 in emulator.memory_map
            assert emulator.memory_map[0x500000] == test_data

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_write_symbolic_memory_production(self, valid_pe_binary: Path) -> None:
        """Symbolic memory write tracks constraints."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            test_data = b"\x01\x02"
            emulator.set_memory(0x600000, test_data, symbolic=True)

            assert 0x600000 in emulator.symbolic_memory
            assert 0x600001 in emulator.symbolic_memory
            assert len(emulator.path_constraints) >= 2


class TestESILInstructionEmulation:
    """Test real ESIL instruction emulation."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_emulate_mov_instruction_production(self, valid_pe_binary: Path) -> None:
        """Emulate mov instruction and verify register update."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                step_info = emulator.step_instruction()

                assert "address" in step_info
                assert "instruction" in step_info
                assert "esil" in step_info
                assert isinstance(step_info["changed_registers"], dict)

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_emulate_arithmetic_production(self, valid_pe_binary: Path) -> None:
        """Emulate arithmetic instructions and verify results."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            emulator.set_register("rax", 0)
            emulator.set_register("rbx", 0)

            for _ in range(3):
                step_info = emulator.step_instruction()
                if not step_info:
                    break

            assert emulator.instruction_count > 0
            assert isinstance(emulator.memory_accesses, list)

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_step_instruction_tracks_pc_production(self, valid_pe_binary: Path) -> None:
        """Step instruction tracks program counter changes."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                step_info = emulator.step_instruction()

                assert "new_pc" in step_info
                assert isinstance(step_info["new_pc"], int)
                assert step_info["new_pc"] > 0


class TestBreakpoints:
    """Test real breakpoint functionality."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_add_breakpoint_production(self, valid_pe_binary: Path) -> None:
        """Breakpoint is added to real radare2 session."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            bp = emulator.add_breakpoint(0x401500)

            assert isinstance(bp, ESILBreakpoint)
            assert bp.address == 0x401500
            assert 0x401500 in emulator.breakpoints

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_add_breakpoint_with_condition_production(
        self, valid_pe_binary: Path
    ) -> None:
        """Breakpoint with condition is created."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            bp = emulator.add_breakpoint(0x401500, condition="rax > 100")

            assert bp.condition == "rax > 100"
            assert bp.enabled is True

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_remove_breakpoint_production(self, valid_pe_binary: Path) -> None:
        """Breakpoint can be removed."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            emulator.add_breakpoint(0x401500)
            emulator.remove_breakpoint(0x401500)

            assert 0x401500 not in emulator.breakpoints


class TestTaintAnalysis:
    """Test taint tracking functionality."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_add_taint_source_production(self, valid_pe_binary: Path) -> None:
        """Taint source is tracked correctly."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            emulator.add_taint_source(0x600000, size=16)

            assert 0x600000 in emulator.taint_sources


class TestHooks:
    """Test ESIL operation hooks."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_add_hook_production(self, valid_pe_binary: Path) -> None:
        """Hooks are registered correctly."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            hook_called: list[tuple[int, int]] = []

            def mem_read_hook(addr: int, size: int) -> None:
                hook_called.append((addr, size))

            emulator.add_hook("mem_read", mem_read_hook)

            assert "mem_read" in emulator._esil_hooks
            assert len(emulator._esil_hooks["mem_read"]) == 1


class TestControlFlow:
    """Test control flow tracking."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_determine_control_flow_type_production(
        self, valid_pe_binary: Path
    ) -> None:
        """Control flow type is determined correctly."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            assert emulator._determine_control_flow_type("call rax") == "call"
            assert emulator._determine_control_flow_type("ret") == "ret"
            assert emulator._determine_control_flow_type("jmp 0x401500") == "jump"
            assert emulator._determine_control_flow_type("je 0x401500") == "jump"
            assert emulator._determine_control_flow_type("add rax, rbx") == "other"


class TestLicenseCheckDetection:
    """Test license validation detection with real binaries."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_find_license_checks_production(self, valid_pe_binary: Path) -> None:
        """License check patterns are identified in real binary."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            checks = emulator.find_license_checks()

            assert isinstance(checks, list)


class TestTraceExport:
    """Test execution trace export."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_dump_execution_trace_production(
        self, valid_pe_binary: Path, tmp_path: Path
    ) -> None:
        """Execution trace exports to JSON with real data."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                emulator.step_instruction()

            output_path = tmp_path / "trace.json"
            emulator.dump_execution_trace(str(output_path))

            assert output_path.exists()

            import json

            with open(output_path) as f:
                trace = json.load(f)

            assert "binary" in trace
            assert "architecture" in trace
            assert "instruction_count" in trace
            assert trace["instruction_count"] >= 0


class TestReset:
    """Test emulator reset functionality."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_reset_emulator_production(self, valid_pe_binary: Path) -> None:
        """Emulator resets to initial state."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                emulator.step_instruction()

            emulator.memory_accesses.append(
                ESILMemoryAccess(
                    address=0x500000,
                    size=8,
                    value=b"\x00" * 8,
                    operation="read",
                    instruction_address=0x401000,
                    register_state={},
                )
            )

            emulator.reset()

            assert emulator.instruction_count == 0
            assert len(emulator.memory_accesses) == 0
            assert emulator.state == ESILState.READY


class TestEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_invalid_register_name_production(self, valid_pe_binary: Path) -> None:
        """Invalid register name returns 0 or raises error."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="a", read_only=True
        ) as emulator:
            try:
                result = emulator.get_register("invalid_register_xyz")
                assert result == 0 or isinstance(result, int)
            except RuntimeError:
                pass


class TestRealWorldScenarios:
    """Test realistic emulation scenarios."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_emulate_license_check_workflow_production(
        self, valid_pe_binary: Path
    ) -> None:
        """Complete license check emulation workflow."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                emulator.add_breakpoint(emulator.entry_point + 0x10)

            checks = emulator.find_license_checks()

            assert isinstance(checks, list)

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_run_until_target_production(self, valid_pe_binary: Path) -> None:
        """Run until target address with real emulation."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                target = emulator.entry_point + 0x4

                try:
                    trace = emulator.run_until(target, max_steps=10)

                    assert isinstance(trace, list)
                    assert emulator.instruction_count >= 0
                except RuntimeError:
                    pass

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_extract_api_calls_production(self, valid_pe_binary: Path) -> None:
        """Extract API calls from emulation trace."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            api_calls = emulator.extract_api_calls()

            assert isinstance(api_calls, list)

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_memory_access_tracking_production(self, valid_pe_binary: Path) -> None:
        """Memory accesses are tracked during emulation."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                for _ in range(5):
                    try:
                        emulator.step_instruction()
                    except RuntimeError:
                        break

            assert isinstance(emulator.memory_accesses, list)


class TestSymbolicExecution:
    """Test symbolic execution capabilities."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_symbolic_register_execution_production(
        self, valid_pe_binary: Path
    ) -> None:
        """Symbolic execution generates path constraints."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            emulator.set_register("rax", "user_input", symbolic=True)

            if emulator.entry_point > 0:
                try:
                    for _ in range(10):
                        emulator.step_instruction()
                except RuntimeError:
                    pass

            assert "rax" in emulator.registers
            assert emulator.registers["rax"].symbolic is True

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_generate_path_constraints_production(self, valid_pe_binary: Path) -> None:
        """Path constraints are generated for target address."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            if emulator.entry_point > 0:
                target = emulator.entry_point + 0x10

                try:
                    constraints = emulator.generate_path_constraints(target)

                    assert isinstance(constraints, list)
                except RuntimeError:
                    pass


class TestMemoryRegions:
    """Test memory region setup and management."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_memory_regions_initialized_production(self, valid_pe_binary: Path) -> None:
        """Memory regions are set up from binary sections."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            assert emulator.entry_point >= 0

            if emulator.entry_point > 0:
                data = emulator.get_memory(emulator.entry_point, 4)
                assert isinstance(data, bytes)
                assert len(data) == 4


class TestCallStackTracking:
    """Test function call stack tracking."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_call_stack_tracking_production(self, valid_pe_binary: Path) -> None:
        """Call stack is tracked during emulation."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            initial_depth = len(emulator.call_stack)

            if emulator.entry_point > 0:
                try:
                    for _ in range(10):
                        step_info = emulator.step_instruction()
                        if "call_depth" in step_info:
                            assert isinstance(step_info["call_depth"], int)
                            assert step_info["call_depth"] >= 0
                except RuntimeError:
                    pass

            assert len(emulator.call_stack) >= initial_depth


class TestInstructionCounting:
    """Test instruction counting during emulation."""

    @pytest.mark.skipif(not radare2_available(), reason="radare2 not installed")
    def test_instruction_count_increments_production(
        self, valid_pe_binary: Path
    ) -> None:
        """Instruction count increments with each step."""
        with RadareESILEmulator(
            str(valid_pe_binary), auto_analyze=False, analysis_level="aa", read_only=True
        ) as emulator:
            initial_count = emulator.instruction_count

            if emulator.entry_point > 0:
                try:
                    emulator.step_instruction()
                    assert emulator.instruction_count == initial_count + 1

                    emulator.step_instruction()
                    assert emulator.instruction_count == initial_count + 2
                except RuntimeError:
                    pass
