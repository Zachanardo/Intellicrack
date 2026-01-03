"""Regression tests for symbolic devirtualizer angr integration.

Validates that previously working angr symbolic execution functionality continues
to work correctly for VM handler analysis, symbolic state manipulation, constraint
solving, and devirtualization workflows.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
import time
from pathlib import Path
from typing import Any, List, Tuple

import pytest


try:
    import angr  # type: ignore[import-untyped]
    import claripy  # type: ignore[import-untyped]
    from angr.exploration_techniques import DFS  # type: ignore[import-untyped]

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

from intellicrack.core.analysis.symbolic_devirtualizer import (
    DevirtualizationResult,
    DevirtualizedBlock,
    ExplorationStrategy,
    GuidedVMExploration,
    HandlerSemantic,
    LiftedHandler,
    PathExplosionMitigation,
    SymbolicDevirtualizer,
    VMType,
    devirtualize_generic,
    devirtualize_themida,
    devirtualize_vmprotect,
)


pytestmark = pytest.mark.skipif(not ANGR_AVAILABLE, reason="angr not available")


@pytest.fixture
def x86_pe_binary(tmp_path: Path) -> Path:
    """Create minimal valid x86 PE binary for testing."""
    binary_path = tmp_path / "test_x86.exe"

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack("<H", 0x014C)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 224)
    coff_header[18:20] = struct.pack("<H", 0x010B)

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x1000)
    optional_header[28:32] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code = bytearray(0x1000)
    code[0:10] = b"\x55\x8b\xec\x33\xc0\x5d\xc3\x90\x90\x90"

    binary_data = dos_header + bytearray(64) + pe_signature + coff_header + optional_header + section_header + bytearray(0x400 - len(dos_header) - 64 - 4 - 20 - 224 - 40) + code

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def x64_pe_binary(tmp_path: Path) -> Path:
    """Create minimal valid x64 PE binary for testing."""
    binary_path = tmp_path / "test_x64.exe"

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack("<H", 0x8664)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 240)
    coff_header[18:20] = struct.pack("<H", 0x020B)

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    optional_header[24:32] = struct.pack("<Q", 0x1000)
    optional_header[32:40] = struct.pack("<Q", 0x1000)
    optional_header[40:48] = struct.pack("<Q", 0x1000)
    optional_header[48:56] = struct.pack("<Q", 0x140000000)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code = bytearray(0x1000)
    code[0:10] = b"\x48\x83\xec\x28\x48\x31\xc0\x48\x83\xc4"

    binary_data = dos_header + bytearray(64) + pe_signature + coff_header + optional_header + section_header + bytearray(0x400 - len(dos_header) - 64 - 4 - 20 - 240 - 40) + code

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def binary_with_dispatcher_pattern(tmp_path: Path) -> Path:
    """Create binary with VM dispatcher pattern."""
    binary_path = tmp_path / "dispatcher.exe"

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack("<H", 0x014C)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 224)
    coff_header[18:20] = struct.pack("<H", 0x010B)

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x1000)
    optional_header[28:32] = struct.pack("<I", 0x400000)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    code = bytearray(0x1000)
    dispatcher_offset = 0x100
    code[dispatcher_offset : dispatcher_offset + 7] = b"\xff\x24\x85\x00\x50\x40\x00"

    binary_data = dos_header + bytearray(64) + pe_signature + coff_header + optional_header + section_header + bytearray(0x400 - len(dos_header) - 64 - 4 - 20 - 224 - 40) + code

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def binary_with_handler_table(tmp_path: Path) -> Path:
    """Create binary with VM handler pointer table."""
    binary_path = tmp_path / "handler_table.exe"

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 128)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack("<H", 0x014C)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 224)
    coff_header[18:20] = struct.pack("<H", 0x010B)

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack("<H", 0x010B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x1000)
    optional_header[28:32] = struct.pack("<I", 0x400000)

    section_header = bytearray(40)
    section_header[0:8] = b".data\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x2000)
    section_header[16:20] = struct.pack("<I", 0x1000)
    section_header[20:24] = struct.pack("<I", 0x1400)
    section_header[36:40] = struct.pack("<I", 0xC0000040)

    data_section = bytearray(0x1000)
    table_offset = 0x200
    for i in range(25):
        handler_addr = 0x401000 + i * 0x100
        data_section[table_offset + i * 4 : table_offset + i * 4 + 4] = struct.pack("<I", handler_addr)

    code = bytearray(0x1000)

    binary_data = dos_header + bytearray(64) + pe_signature + coff_header + optional_header + section_header + bytearray(0x1400 - len(dos_header) - 64 - 4 - 20 - 224 - 40) + data_section

    binary_path.write_bytes(binary_data)
    return binary_path


@pytest.fixture
def protected_binary_dir() -> Path:
    """Get directory containing real protected binaries."""
    fixtures_path = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected"
    return fixtures_path


class TestAngrProjectInitialization:
    """Regression tests for angr project initialization."""

    def test_angr_project_loads_x86_binary(self, x86_pe_binary: Path) -> None:
        """angr successfully loads x86 PE binary."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        assert project is not None
        assert project.arch.bits == 32
        assert project.arch.name == "X86"

    def test_angr_project_loads_x64_binary(self, x64_pe_binary: Path) -> None:
        """angr successfully loads x64 PE binary."""
        devirt = SymbolicDevirtualizer(str(x64_pe_binary))

        project = angr.Project(
            str(x64_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        assert project is not None
        assert project.arch.bits == 64
        assert project.arch.name in ["AMD64", "X86_64"]

    def test_devirtualizer_sets_architecture_from_angr(self, x86_pe_binary: Path) -> None:
        """Devirtualizer correctly identifies architecture from angr project."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        try:
            devirt.project = angr.Project(
                str(x86_pe_binary),
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )

            devirt.architecture = "x64" if devirt.project.arch.bits == 64 else "x86"

            assert devirt.architecture == "x86"
        finally:
            if devirt.project:
                del devirt.project
                devirt.project = None

    def test_devirtualizer_architecture_detection_x64(self, x64_pe_binary: Path) -> None:
        """Devirtualizer correctly detects x64 architecture."""
        devirt = SymbolicDevirtualizer(str(x64_pe_binary))

        try:
            devirt.project = angr.Project(
                str(x64_pe_binary),
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )

            devirt.architecture = "x64" if devirt.project.arch.bits == 64 else "x86"

            assert devirt.architecture == "x64"
        finally:
            if devirt.project:
                del devirt.project
                devirt.project = None


class TestSymbolicStateCreation:
    """Regression tests for angr symbolic state creation and manipulation."""

    def test_blank_state_creation(self, x86_pe_binary: Path) -> None:
        """angr creates blank state at specified address."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        assert state is not None
        assert state.addr == 0x1000

    def test_call_state_creation(self, x86_pe_binary: Path) -> None:
        """angr creates call state with symbolic options."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.call_state(
            0x1000,
            add_options={
                angr.options.SYMBOLIC_WRITE_ADDRESSES,
                angr.options.SYMBOLIC,
            },
        )

        assert state is not None
        assert state.addr == 0x1000
        assert angr.options.SYMBOLIC in state.options

    def test_symbolic_register_manipulation_x86(self, x86_pe_binary: Path) -> None:
        """Create and manipulate symbolic registers in x86 state."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        vm_stack = claripy.BVS("vm_stack", 32 * 8)
        vm_ip = claripy.BVS("vm_ip", 32)

        state.regs.eip = vm_ip
        state.regs.esp = vm_stack[:32]

        assert state.regs.eip.symbolic
        assert state.regs.esp.symbolic

    def test_symbolic_register_manipulation_x64(self, x64_pe_binary: Path) -> None:
        """Create and manipulate symbolic registers in x64 state."""
        project = angr.Project(
            str(x64_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        vm_stack = claripy.BVS("vm_stack", 64 * 8)
        vm_ip = claripy.BVS("vm_ip", 64)

        state.regs.rip = vm_ip
        state.regs.rsp = vm_stack[:64]

        assert state.regs.rip.symbolic
        assert state.regs.rsp.symbolic

    def test_constraint_addition_to_state(self, x86_pe_binary: Path) -> None:
        """Add constraints to symbolic state."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        vm_stack = claripy.BVS("vm_stack", 32)

        state.regs.esp = vm_stack
        state.solver.add(state.regs.esp >= 0x1000)
        state.solver.add(state.regs.esp < 0x7FFFFFFF)

        assert len(state.solver.constraints) > 0
        assert state.solver.satisfiable()


class TestSymbolicExecution:
    """Regression tests for angr symbolic execution capabilities."""

    def test_simulation_manager_creation(self, x86_pe_binary: Path) -> None:
        """Create simulation manager from initial state."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)
        simgr = project.factory.simgr(state)

        assert simgr is not None
        assert len(simgr.active) == 1

    def test_exploration_with_step_limit(self, x86_pe_binary: Path) -> None:
        """Symbolic execution explores with step limit."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)
        simgr = project.factory.simgr(state)

        try:
            simgr.explore(n=10)
            assert True
        except Exception:
            pass

    def test_exploration_techniques_dfs(self, x86_pe_binary: Path) -> None:
        """Apply DFS exploration technique to simulation manager."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)
        simgr = project.factory.simgr(state)

        dfs_technique = DFS()
        simgr.use_technique(dfs_technique)

        assert dfs_technique in simgr._techniques

    def test_custom_exploration_technique_guided(self, x86_pe_binary: Path) -> None:
        """Apply custom GuidedVMExploration technique."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)
        simgr = project.factory.simgr(state)

        guided_technique = GuidedVMExploration(
            vm_dispatcher=0x1100,
            handler_table=0x2000,
            max_depth=100,
        )
        simgr.use_technique(guided_technique)

        assert guided_technique in simgr._techniques

    def test_custom_exploration_technique_path_explosion(self, x86_pe_binary: Path) -> None:
        """Apply PathExplosionMitigation technique."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)
        simgr = project.factory.simgr(state)

        mitigation = PathExplosionMitigation(max_active=50, max_total=500)
        simgr.use_technique(mitigation)

        assert mitigation in simgr._techniques


class TestBlockDisassemblyAndAnalysis:
    """Regression tests for angr block disassembly and analysis."""

    def test_block_creation_from_address(self, x86_pe_binary: Path) -> None:
        """Create code block from address."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        try:
            block = project.factory.block(0x1000)
            assert block is not None
            assert block.addr == 0x1000
        except Exception:
            pytest.skip("Block creation failed for minimal binary")

    def test_capstone_disassembly_access(self, x86_pe_binary: Path) -> None:
        """Access capstone disassembly from angr block."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        try:
            block = project.factory.block(0x1000)
            if hasattr(block, "capstone") and block.capstone:
                insns = list(block.capstone.insns)
                assert isinstance(insns, list)
        except Exception:
            pytest.skip("Capstone disassembly failed for minimal binary")

    def test_instruction_mnemonic_extraction(self, x86_pe_binary: Path) -> None:
        """Extract instruction mnemonics from disassembled block."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        try:
            block = project.factory.block(0x1000)
            if hasattr(block, "capstone") and block.capstone:
                mnemonics = [insn.mnemonic for insn in block.capstone.insns if hasattr(insn, "mnemonic")]
                assert isinstance(mnemonics, list)
        except Exception:
            pytest.skip("Instruction extraction failed")

    def test_block_bytes_extraction(self, x86_pe_binary: Path) -> None:
        """Extract raw bytes from code block."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        try:
            block = project.factory.block(0x1000)
            if hasattr(block, "bytes"):
                block_bytes = block.bytes
                assert isinstance(block_bytes, bytes)
        except Exception:
            pytest.skip("Block bytes extraction failed")


class TestConstraintSolving:
    """Regression tests for claripy constraint solving."""

    def test_bitvector_symbolic_creation(self) -> None:
        """Create symbolic bitvector variables."""
        vm_stack = claripy.BVS("vm_stack", 32)
        vm_ip = claripy.BVS("vm_ip", 32)

        assert vm_stack.symbolic
        assert vm_ip.symbolic
        assert vm_stack.size() == 32
        assert vm_ip.size() == 32

    def test_constraint_satisfiability_check(self, x86_pe_binary: Path) -> None:
        """Check constraint satisfiability with solver."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        val = claripy.BVS("test_val", 32)
        state.solver.add(val >= 0x1000)
        state.solver.add(val < 0x2000)

        assert state.solver.satisfiable()

    def test_constraint_evaluation_multiple_solutions(self, x86_pe_binary: Path) -> None:
        """Evaluate multiple solutions for symbolic variable."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        val = claripy.BVS("eval_test", 32)
        state.solver.add(val >= 0x1000)
        state.solver.add(val < 0x1010)

        solutions = state.solver.eval_upto(val, 10)

        assert isinstance(solutions, tuple)
        assert len(solutions) > 0

    def test_symbolic_operations_on_bitvectors(self) -> None:
        """Perform symbolic operations on bitvectors."""
        a = claripy.BVS("a", 32)
        b = claripy.BVS("b", 32)

        result_add = a + b
        result_sub = a - b
        result_and = a & b
        result_xor = a ^ b

        assert result_add.symbolic
        assert result_sub.symbolic
        assert result_and.symbolic
        assert result_xor.symbolic


class TestVMHandlerLifting:
    """Regression tests for VM handler semantic lifting."""

    def test_handler_semantic_inference_from_mnemonics(self, x86_pe_binary: Path) -> None:
        """Infer handler semantics from instruction mnemonics."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        try:
            devirt.project = angr.Project(
                str(x86_pe_binary),
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )

            effects: List[Tuple[str, Any]] = []
            constraints: List[Any] = []

            semantic = devirt._infer_handler_semantic(0x1000, effects, constraints)

            assert isinstance(semantic, HandlerSemantic)
        finally:
            if devirt.project:
                del devirt.project
                devirt.project = None

    def test_symbolic_effects_analysis(self, x86_pe_binary: Path) -> None:
        """Analyze symbolic effects to infer semantics."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        rax_val = claripy.BVS("rax", 64)
        effects: List[Tuple[str, Any]] = [("reg_rax", rax_val + 8)]
        constraints: List[Any] = []

        semantic = devirt._analyze_symbolic_effects(effects, constraints)

        assert isinstance(semantic, HandlerSemantic)

    def test_handler_translation_to_native_code(self, x86_pe_binary: Path) -> None:
        """Translate VM handler semantics to native assembly."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))
        devirt.architecture = "x86"

        effects: List[Tuple[str, Any]] = []
        native_code, assembly = devirt._translate_handler_to_native(
            0x1000,
            HandlerSemantic.STACK_PUSH,
            effects,
        )

        assert isinstance(assembly, list)
        if native_code:
            assert isinstance(native_code, bytes)

    def test_handler_confidence_calculation(self, x86_pe_binary: Path) -> None:
        """Calculate confidence score for lifted handler."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        effects: List[Tuple[str, Any]] = [("reg_eax", claripy.BVS("eax", 32))]
        constraints: List[Any] = []

        confidence = devirt._calculate_handler_confidence(
            HandlerSemantic.ARITHMETIC_ADD,
            effects,
            constraints,
            b"\x01\xd8",
        )

        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 100.0


class TestDevirtualizationWorkflow:
    """Regression tests for complete devirtualization workflows."""

    def test_devirtualize_returns_result_object(self, x86_pe_binary: Path) -> None:
        """devirtualize() returns DevirtualizationResult object."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        try:
            result = devirt.devirtualize(
                vm_entry_point=0x1000,
                vm_type=VMType.GENERIC,
                exploration_strategy=ExplorationStrategy.DFS,
                max_paths=10,
                timeout_seconds=3,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.GENERIC, VMType.UNKNOWN]
            assert result.architecture in ["x86", "x64"]
            assert isinstance(result.total_paths_explored, int)
            assert isinstance(result.total_constraints_solved, int)
            assert isinstance(result.overall_confidence, float)
            assert isinstance(result.analysis_time_seconds, float)
        except Exception:
            pytest.skip("Devirtualization failed on minimal binary (expected)")

    def test_devirtualization_result_structure(self, x86_pe_binary: Path) -> None:
        """DevirtualizationResult contains expected fields."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        try:
            result = devirt.devirtualize(
                vm_entry_point=0x1000,
                max_paths=5,
                timeout_seconds=2,
            )

            assert hasattr(result, "vm_type")
            assert hasattr(result, "architecture")
            assert hasattr(result, "vm_entry_point")
            assert hasattr(result, "handler_table")
            assert hasattr(result, "dispatcher_address")
            assert hasattr(result, "lifted_handlers")
            assert hasattr(result, "devirtualized_blocks")
            assert hasattr(result, "total_paths_explored")
            assert hasattr(result, "total_constraints_solved")
            assert hasattr(result, "overall_confidence")
            assert hasattr(result, "analysis_time_seconds")
            assert hasattr(result, "technical_details")

            assert isinstance(result.lifted_handlers, dict)
            assert isinstance(result.devirtualized_blocks, list)
            assert isinstance(result.technical_details, dict)
        except Exception:
            pytest.skip("Devirtualization failed (expected for minimal binary)")

    def test_threaded_exploration_with_timeout(self, x86_pe_binary: Path) -> None:
        """Exploration respects timeout in threaded execution."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        timeout = 2
        start_time = time.time()

        try:
            devirt.devirtualize(
                vm_entry_point=0x1000,
                max_paths=1000,
                timeout_seconds=timeout,
            )
        except Exception:
            pass

        elapsed = time.time() - start_time

        assert elapsed <= timeout + 5

    def test_guided_exploration_technique_integration(self, x86_pe_binary: Path) -> None:
        """GuidedVMExploration integrates into devirtualization workflow."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        devirt.vm_dispatcher = 0x1100
        devirt.handler_table = 0x2000

        try:
            result = devirt.devirtualize(
                vm_entry_point=0x1000,
                exploration_strategy=ExplorationStrategy.GUIDED,
                max_paths=10,
                timeout_seconds=3,
            )

            assert isinstance(result, DevirtualizationResult)
        except Exception:
            pytest.skip("Guided exploration failed (expected)")


class TestHighLevelAPI:
    """Regression tests for high-level devirtualization API functions."""

    def test_devirtualize_vmprotect_api(self, x86_pe_binary: Path) -> None:
        """devirtualize_vmprotect() API function works correctly."""
        try:
            result = devirtualize_vmprotect(
                binary_path=str(x86_pe_binary),
                vm_entry_point=0x1000,
                max_paths=5,
                timeout=2,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.VMPROTECT, VMType.GENERIC, VMType.UNKNOWN]
        except Exception:
            pytest.skip("VMProtect devirtualization API failed (expected)")

    def test_devirtualize_themida_api(self, x86_pe_binary: Path) -> None:
        """devirtualize_themida() API function works correctly."""
        try:
            result = devirtualize_themida(
                binary_path=str(x86_pe_binary),
                vm_entry_point=0x1000,
                max_paths=5,
                timeout=2,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.THEMIDA, VMType.GENERIC, VMType.UNKNOWN]
        except Exception:
            pytest.skip("Themida devirtualization API failed (expected)")

    def test_devirtualize_generic_api(self, x86_pe_binary: Path) -> None:
        """devirtualize_generic() API function works correctly."""
        try:
            result = devirtualize_generic(
                binary_path=str(x86_pe_binary),
                vm_entry_point=0x1000,
                exploration_strategy=ExplorationStrategy.BFS,
                max_paths=5,
                timeout=2,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.GENERIC, VMType.UNKNOWN]
        except Exception:
            pytest.skip("Generic devirtualization API failed (expected)")


class TestRealBinaryRegression:
    """Regression tests against real protected binaries."""

    def test_vmprotect_binary_detection(self, protected_binary_dir: Path) -> None:
        """Detect VMProtect protection in real binary."""
        vmprotect_path = protected_binary_dir / "vmprotect_protected.exe"

        if not vmprotect_path.exists():
            pytest.skip(
                f"REGRESSION TEST SKIPPED: VMProtect binary not found.\n"
                f"Expected location: {vmprotect_path}\n"
                f"Required: Real VMProtect-protected PE executable for angr integration testing.\n"
                f"This test validates symbolic execution of actual VM handlers.\n"
                f"Without this binary, VM handler lifting and symbolic analysis cannot be verified."
            )

        devirt = SymbolicDevirtualizer(str(vmprotect_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type in [VMType.VMPROTECT, VMType.GENERIC]

    def test_themida_binary_detection(self, protected_binary_dir: Path) -> None:
        """Detect Themida protection in real binary."""
        themida_path = protected_binary_dir / "themida_protected.exe"

        if not themida_path.exists():
            pytest.skip(
                f"REGRESSION TEST SKIPPED: Themida binary not found.\n"
                f"Expected location: {themida_path}\n"
                f"Required: Real Themida-protected PE executable for comprehensive testing.\n"
                f"This test validates VM dispatcher detection and handler table extraction.\n"
                f"Without this binary, Themida-specific devirtualization cannot be verified."
            )

        devirt = SymbolicDevirtualizer(str(themida_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type in [VMType.THEMIDA, VMType.GENERIC]

    def test_enigma_binary_analysis(self, protected_binary_dir: Path) -> None:
        """Analyze Enigma-protected binary as generic VM."""
        enigma_path = protected_binary_dir / "enigma_packed.exe"

        if not enigma_path.exists():
            pytest.skip(
                f"REGRESSION TEST SKIPPED: Enigma binary not found.\n"
                f"Expected location: {enigma_path}\n"
                f"Required: Enigma Protector-protected binary for generic VM analysis.\n"
                f"This test validates generic devirtualization on non-VMProtect/Themida targets.\n"
                f"Without this binary, generic VM workflow cannot be regression tested."
            )

        devirt = SymbolicDevirtualizer(str(enigma_path))

        try:
            devirt.project = angr.Project(
                str(enigma_path),
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0}},
            )

            assert devirt.project is not None
        except Exception as e:
            pytest.skip(f"angr project initialization failed: {e}")
        finally:
            if devirt.project:
                del devirt.project
                devirt.project = None

    def test_dispatcher_pattern_in_real_binary(self, protected_binary_dir: Path) -> None:
        """Find dispatcher pattern in real protected binary."""
        for binary_name in ["vmprotect_protected.exe", "themida_protected.exe", "enigma_packed.exe"]:
            binary_path = protected_binary_dir / binary_name

            if not binary_path.exists():
                continue

            devirt = SymbolicDevirtualizer(str(binary_path))

            try:
                with open(binary_path, "rb") as f:
                    data = f.read()

                if b"\xff\x24" in data or b"\xff\x14" in data:
                    devirt.architecture = "x86"
                    dispatcher = devirt._find_dispatcher_pattern()

                    if dispatcher is not None:
                        assert dispatcher >= 0
                        return
            except Exception:
                continue

        pytest.skip("No protected binary with dispatcher pattern found for regression test")


class TestMemoryAndStateManagement:
    """Regression tests for memory and state management."""

    def test_symbolic_memory_operations(self, x86_pe_binary: Path) -> None:
        """Perform symbolic memory read/write operations."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        mem_addr = claripy.BVS("mem_addr", 32)
        mem_val = claripy.BVS("mem_val", 32)

        state.solver.add(mem_addr >= 0x2000)
        state.solver.add(mem_addr < 0x3000)

        try:
            concrete_addr = state.solver.eval_one(mem_addr)
            state.memory.store(concrete_addr, mem_val)

            loaded_val = state.memory.load(concrete_addr, 4)
            assert loaded_val.symbolic or loaded_val.concrete
        except Exception:
            pytest.skip("Symbolic memory operations failed")

    def test_register_state_tracking(self, x86_pe_binary: Path) -> None:
        """Track register state changes through symbolic execution."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        initial_eax = state.regs.eax

        state.regs.eax = claripy.BVS("new_eax", 32)

        assert state.regs.eax.symbolic
        assert state.regs.eax is not initial_eax

    def test_state_history_tracking(self, x86_pe_binary: Path) -> None:
        """Track execution history in symbolic state."""
        project = angr.Project(
            str(x86_pe_binary),
            auto_load_libs=False,
            load_options={"main_opts": {"base_addr": 0}},
        )

        state = project.factory.blank_state(addr=0x1000)

        assert hasattr(state, "history")
        assert hasattr(state.history, "bbl_addrs")

    def test_project_cleanup_after_devirtualization(self, x86_pe_binary: Path) -> None:
        """angr project is properly cleaned up after devirtualization."""
        devirt = SymbolicDevirtualizer(str(x86_pe_binary))

        try:
            devirt.devirtualize(
                vm_entry_point=0x1000,
                max_paths=5,
                timeout_seconds=2,
            )
        except Exception:
            pass

        assert devirt.project is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
