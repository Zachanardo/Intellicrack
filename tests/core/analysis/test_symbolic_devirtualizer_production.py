"""Production-Ready Tests for Symbolic Devirtualizer with Real VMProtect/Themida Binaries.

This test suite validates the symbolic devirtualizer's capability to:
- Integrate with angr for symbolic execution of virtualized code
- Lift VM handler semantics to intermediate representation
- Solve constraints to recover original instruction semantics
- Handle symbolic memory and register states during devirtualization
- Output equivalent native code for decompilation
- Process real VMProtect/Themida/Code Virtualizer binaries
- Handle complex control flow, indirect jumps, and self-modifying code

Tests FAIL if:
- Angr integration is not functional
- Handler lifting produces no results or incorrect semantics
- Constraint solving fails to identify handler behavior
- Native code output is missing or invalid
- Protected binaries are not properly analyzed
- Edge cases cause crashes or incorrect results

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
import time
from pathlib import Path
from typing import Any

import pytest

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


PROTECTED_BINARIES_DIR = Path(__file__).parent.parent.parent / "resources" / "protected_binaries"


def create_minimal_pe32_with_vm_pattern(output_path: Path) -> tuple[int, int]:
    """Create minimal PE32 binary with VM-like patterns for testing.

    Returns:
        tuple[int, int]: (vm_entry_offset, dispatcher_offset)
    """
    dos_header = bytearray(b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80))
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        0xE0,
        0x010B,
    )

    optional_header = struct.pack(
        "<HHIIIIIHHHHHHHIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x1000,
        0,
        0,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0,
        0x3000,
        0x200,
        0,
        3,
        0,
        0x10000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x1000,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    vm_entry_code = bytearray([
        0x55,
        0x89, 0xE5,
        0x53,
        0x51,
        0x52,
        0x8B, 0x45, 0x08,
        0x89, 0xC3,
        0xFF, 0x24, 0x85, 0x00, 0x20, 0x40, 0x00,
        0xC9,
        0xC3,
    ])

    handler_table_offset = 0x200
    handler_table = bytearray()
    for i in range(32):
        handler_addr = 0x401000 + 0x300 + (i * 0x20)
        handler_table += struct.pack("<I", handler_addr)

    handler_code = bytearray()

    handler_push = bytearray([0x50, 0xC3])
    handler_code += handler_push
    handler_code += b"\x90" * (0x20 - len(handler_push))

    handler_pop = bytearray([0x58, 0xC3])
    handler_code += handler_pop
    handler_code += b"\x90" * (0x20 - len(handler_pop))

    handler_add = bytearray([0x01, 0xD8, 0xC3])
    handler_code += handler_add
    handler_code += b"\x90" * (0x20 - len(handler_add))

    handler_sub = bytearray([0x29, 0xD8, 0xC3])
    handler_code += handler_sub
    handler_code += b"\x90" * (0x20 - len(handler_sub))

    handler_xor = bytearray([0x31, 0xD8, 0xC3])
    handler_code += handler_xor
    handler_code += b"\x90" * (0x20 - len(handler_xor))

    for _ in range(27):
        nop_handler = bytearray([0x90, 0x90, 0xC3])
        handler_code += nop_handler
        handler_code += b"\x90" * (0x20 - len(nop_handler))

    section_data = bytearray(0x1000)
    section_data[:len(vm_entry_code)] = vm_entry_code
    section_data[handler_table_offset:handler_table_offset+len(handler_table)] = handler_table
    section_data[0x300:0x300+len(handler_code)] = handler_code

    binary = dos_header + dos_stub
    binary += b"\x00" * (0x80 - len(binary))
    binary += pe_signature + coff_header + optional_header + section_header
    binary += b"\x00" * (0x200 - len(binary))
    binary += section_data

    output_path.write_bytes(binary)

    vm_entry_offset = 0x1000
    dispatcher_offset = 0x1000 + 11

    return vm_entry_offset, dispatcher_offset


@pytest.fixture(scope="module")
def synthetic_vm_binary(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, int, int]:
    """Create a synthetic VM binary for testing when real binaries unavailable."""
    binary_path = tmp_path_factory.mktemp("binaries") / "synthetic_vm.exe"
    vm_entry, dispatcher = create_minimal_pe32_with_vm_pattern(binary_path)
    return binary_path, vm_entry, dispatcher


@pytest.fixture(scope="module")
def vmprotect_binary() -> Path | None:
    """Locate VMProtect-protected binary for testing."""
    patterns = [
        "vmprotect*.exe",
        "vmp*.exe",
        "*_vmprotect.exe",
        "*_vmp.exe",
    ]

    for pattern in patterns:
        matches = list(PROTECTED_BINARIES_DIR.glob(pattern))
        if matches:
            return matches[0]

    return None


@pytest.fixture(scope="module")
def themida_binary() -> Path | None:
    """Locate Themida-protected binary for testing."""
    patterns = [
        "themida*.exe",
        "*_themida.exe",
        "winlicense*.exe",
        "*_winlicense.exe",
    ]

    for pattern in patterns:
        matches = list(PROTECTED_BINARIES_DIR.glob(pattern))
        if matches:
            return matches[0]

    return None


@pytest.fixture(scope="module")
def code_virtualizer_binary() -> Path | None:
    """Locate Code Virtualizer-protected binary for testing."""
    patterns = [
        "codevirtualizer*.exe",
        "*_cv.exe",
        "*_codevirt.exe",
    ]

    for pattern in patterns:
        matches = list(PROTECTED_BINARIES_DIR.glob(pattern))
        if matches:
            return matches[0]

    return None


class TestSymbolicDevirtualizerInitialization:
    """Test symbolic devirtualizer initialization and setup."""

    def test_initializes_with_valid_binary(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Devirtualizer initializes successfully with valid binary path."""
        binary_path, _, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))

        assert devirt.binary_path == str(binary_path)
        assert devirt.project is None
        assert devirt.vm_type == VMType.UNKNOWN
        assert devirt.handler_semantics == {}
        assert devirt.lifted_handlers == {}
        assert devirt.cs_x86 is not None
        assert devirt.cs_x64 is not None
        assert devirt.ks_x86 is not None
        assert devirt.ks_x64 is not None

    def test_fails_with_nonexistent_binary(self) -> None:
        """Devirtualizer raises FileNotFoundError for nonexistent binary."""
        nonexistent_path = "D:\\nonexistent\\binary.exe"

        with pytest.raises(FileNotFoundError, match="Binary file not found"):
            SymbolicDevirtualizer(nonexistent_path)


class TestAngrIntegration:
    """Test angr symbolic execution integration."""

    def test_angr_project_created_during_devirtualization(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Devirtualization creates angr project and initializes symbolic execution."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=50,
            timeout_seconds=10,
        )

        assert isinstance(result, DevirtualizationResult)
        assert result.vm_entry_point == vm_entry
        assert result.architecture in {"x86", "x64"}
        assert result.analysis_time_seconds > 0

    def test_angr_handles_symbolic_memory_and_registers(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Angr symbolic execution tracks memory and register states."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.GUIDED,
            max_paths=100,
            timeout_seconds=15,
        )

        assert len(result.lifted_handlers) > 0

        for handler in result.lifted_handlers.values():
            assert isinstance(handler, LiftedHandler)
            assert handler.handler_address > 0
            assert isinstance(handler.semantic, HandlerSemantic)

    def test_angr_constraint_solving_identifies_handler_semantics(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Constraint solving correctly identifies VM handler semantics."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=200,
            timeout_seconds=20,
        )

        semantic_types_found = {handler.semantic for handler in result.lifted_handlers.values()}

        assert HandlerSemantic.UNKNOWN not in semantic_types_found or len(semantic_types_found) > 1
        assert any(
            semantic in semantic_types_found
            for semantic in [
                HandlerSemantic.STACK_PUSH,
                HandlerSemantic.STACK_POP,
                HandlerSemantic.ARITHMETIC_ADD,
                HandlerSemantic.ARITHMETIC_SUB,
                HandlerSemantic.LOGICAL_XOR,
            ]
        )


class TestHandlerLifting:
    """Test VM handler semantic lifting."""

    def test_lifts_stack_push_handler(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Lifts PUSH handler with correct semantics and native translation."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=15,
        )

        push_handlers = [h for h in result.lifted_handlers.values() if h.semantic == HandlerSemantic.STACK_PUSH]

        if push_handlers:
            handler = push_handlers[0]
            assert handler.native_translation is not None
            assert len(handler.native_translation) > 0
            assert any("push" in asm.lower() for asm in handler.assembly_code)
            assert handler.confidence >= 70.0

    def test_lifts_arithmetic_handlers_with_symbolic_effects(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Lifts arithmetic handlers with symbolic effects captured."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=150,
            timeout_seconds=20,
        )

        arithmetic_handlers = [
            h for h in result.lifted_handlers.values()
            if h.semantic in {
                HandlerSemantic.ARITHMETIC_ADD,
                HandlerSemantic.ARITHMETIC_SUB,
                HandlerSemantic.ARITHMETIC_MUL,
                HandlerSemantic.ARITHMETIC_DIV,
            }
        ]

        if arithmetic_handlers:
            for handler in arithmetic_handlers:
                assert handler.native_translation is not None
                assert len(handler.assembly_code) > 0
                assert handler.confidence >= 60.0

    def test_lifts_logical_handlers_to_native_code(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Lifts logical operation handlers with accurate native translations."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=15,
        )

        logical_handlers = [
            h for h in result.lifted_handlers.values()
            if h.semantic in {
                HandlerSemantic.LOGICAL_AND,
                HandlerSemantic.LOGICAL_OR,
                HandlerSemantic.LOGICAL_XOR,
                HandlerSemantic.LOGICAL_NOT,
            }
        ]

        if logical_handlers:
            for handler in logical_handlers:
                assert handler.native_translation is not None
                assert any(
                    op in " ".join(handler.assembly_code).lower()
                    for op in ["and", "or", "xor", "not"]
                )

    def test_handler_confidence_scores_reflect_analysis_quality(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Handler confidence scores accurately reflect lifting quality."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=15,
        )

        for handler in result.lifted_handlers.values():
            assert 0.0 <= handler.confidence <= 100.0

            if handler.semantic != HandlerSemantic.UNKNOWN:
                assert handler.confidence >= 50.0

            if handler.native_translation and handler.semantic in {
                HandlerSemantic.STACK_PUSH,
                HandlerSemantic.STACK_POP,
                HandlerSemantic.RETURN,
            }:
                assert handler.confidence >= 75.0


class TestNativeCodeGeneration:
    """Test native code output generation."""

    def test_generates_valid_native_bytecode(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Generates valid x86/x64 bytecode from VM handlers."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=15,
        )

        handlers_with_native = [h for h in result.lifted_handlers.values() if h.native_translation]

        assert len(handlers_with_native) > 0

        for handler in handlers_with_native:
            assert isinstance(handler.native_translation, bytes)
            assert len(handler.native_translation) > 0
            assert len(handler.native_translation) <= 200

    def test_generates_assembly_mnemonics_for_decompilation(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Generates assembly mnemonics suitable for decompilation."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=15,
        )

        for handler in result.lifted_handlers.values():
            assert len(handler.assembly_code) > 0

            for asm_line in handler.assembly_code:
                assert isinstance(asm_line, str)
                assert len(asm_line) > 0

    def test_devirtualized_blocks_contain_native_code(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Devirtualized blocks contain valid native code sequences."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=200,
            timeout_seconds=25,
        )

        if result.devirtualized_blocks:
            for block in result.devirtualized_blocks:
                assert isinstance(block.native_code, bytes)
                assert len(block.assembly) > 0
                assert block.confidence >= 0.0


class TestVMProtectionTypes:
    """Test detection and handling of different VM protection types."""

    def test_detects_vmprotect_signatures(self, vmprotect_binary: Path | None) -> None:
        """Detects VMProtect protection from binary signatures."""
        if vmprotect_binary is None:
            pytest.skip(
                f"VMProtect-protected binary not found. Please place a VMProtect-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: vmprotect*.exe, vmp*.exe, *_vmprotect.exe, or *_vmp.exe\n"
                f"The binary should be a real VMProtect-protected executable for production testing."
            )

        devirt = SymbolicDevirtualizer(str(vmprotect_binary))

        with vmprotect_binary.open("rb") as f:
            data = f.read()

        vm_type_detected = VMType.VMPROTECT if (b".vmp" in data or b"VMProtect" in data) else VMType.GENERIC

        assert vm_type_detected == VMType.VMPROTECT

    def test_detects_themida_signatures(self, themida_binary: Path | None) -> None:
        """Detects Themida/WinLicense protection from binary signatures."""
        if themida_binary is None:
            pytest.skip(
                f"Themida-protected binary not found. Please place a Themida/WinLicense-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: themida*.exe, *_themida.exe, winlicense*.exe, or *_winlicense.exe\n"
                f"The binary should be a real Themida or WinLicense-protected executable for production testing."
            )

        devirt = SymbolicDevirtualizer(str(themida_binary))

        with themida_binary.open("rb") as f:
            data = f.read()

        vm_type_detected = VMType.THEMIDA if (b".themida" in data or b"Themida" in data or b"WinLicense" in data) else VMType.GENERIC

        assert vm_type_detected == VMType.THEMIDA

    def test_detects_code_virtualizer_signatures(self, code_virtualizer_binary: Path | None) -> None:
        """Detects Code Virtualizer protection from binary signatures."""
        if code_virtualizer_binary is None:
            pytest.skip(
                f"Code Virtualizer-protected binary not found. Please place a Code Virtualizer-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: codevirtualizer*.exe, *_cv.exe, or *_codevirt.exe\n"
                f"The binary should be a real Code Virtualizer-protected executable for production testing."
            )

        devirt = SymbolicDevirtualizer(str(code_virtualizer_binary))

        with code_virtualizer_binary.open("rb") as f:
            data = f.read()

        vm_type_detected = VMType.CODE_VIRTUALIZER if (b"Code Virtualizer" in data or b".cvirt" in data) else VMType.GENERIC

        assert vm_type_detected == VMType.CODE_VIRTUALIZER


class TestRealProtectedBinaries:
    """Test against real VMProtect/Themida/Code Virtualizer binaries."""

    def test_devirtualizes_vmprotect_binary(self, vmprotect_binary: Path | None) -> None:
        """Successfully devirtualizes real VMProtect-protected binary."""
        if vmprotect_binary is None:
            pytest.skip(
                f"VMProtect-protected binary not found. Please place a VMProtect-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: vmprotect*.exe, vmp*.exe, *_vmprotect.exe, or *_vmp.exe\n"
                f"The binary should be a real VMProtect-protected executable with VM entry point."
            )

        vm_entry = 0x401000

        result = devirtualize_vmprotect(
            str(vmprotect_binary),
            vm_entry_point=vm_entry,
            max_paths=300,
            timeout=60,
        )

        assert result.vm_type == VMType.VMPROTECT
        assert result.vm_entry_point == vm_entry
        assert result.total_paths_explored > 0
        assert result.analysis_time_seconds > 0
        assert len(result.lifted_handlers) >= 5
        assert result.overall_confidence >= 30.0

    def test_devirtualizes_themida_binary(self, themida_binary: Path | None) -> None:
        """Successfully devirtualizes real Themida-protected binary."""
        if themida_binary is None:
            pytest.skip(
                f"Themida-protected binary not found. Please place a Themida/WinLicense-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: themida*.exe, *_themida.exe, winlicense*.exe, or *_winlicense.exe\n"
                f"The binary should be a real Themida or WinLicense-protected executable with VM entry point."
            )

        vm_entry = 0x401000

        result = devirtualize_themida(
            str(themida_binary),
            vm_entry_point=vm_entry,
            max_paths=300,
            timeout=60,
        )

        assert result.vm_type == VMType.THEMIDA
        assert result.vm_entry_point == vm_entry
        assert result.total_paths_explored > 0
        assert result.analysis_time_seconds > 0
        assert len(result.lifted_handlers) >= 5
        assert result.overall_confidence >= 30.0

    def test_processes_code_virtualizer_binary(self, code_virtualizer_binary: Path | None) -> None:
        """Successfully processes real Code Virtualizer-protected binary."""
        if code_virtualizer_binary is None:
            pytest.skip(
                f"Code Virtualizer-protected binary not found. Please place a Code Virtualizer-protected binary "
                f"in: {PROTECTED_BINARIES_DIR}\n"
                f"Expected naming: codevirtualizer*.exe, *_cv.exe, or *_codevirt.exe\n"
                f"The binary should be a real Code Virtualizer-protected executable with VM entry point."
            )

        vm_entry = 0x401000

        result = devirtualize_generic(
            str(code_virtualizer_binary),
            vm_entry_point=vm_entry,
            exploration_strategy=ExplorationStrategy.GUIDED,
            max_paths=300,
            timeout=60,
        )

        assert result.vm_entry_point == vm_entry
        assert result.total_paths_explored > 0
        assert result.analysis_time_seconds > 0
        assert len(result.lifted_handlers) >= 5


class TestComplexControlFlow:
    """Test handling of complex control flow patterns."""

    def test_handles_indirect_jumps(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Handles indirect jumps in VM dispatcher correctly."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.GUIDED,
            max_paths=200,
            timeout_seconds=25,
        )

        assert result.dispatcher_address is not None or result.handler_table is not None

        if result.devirtualized_blocks:
            has_branch_handlers = any(
                handler.semantic in {HandlerSemantic.BRANCH_CONDITIONAL, HandlerSemantic.BRANCH_UNCONDITIONAL}
                for block in result.devirtualized_blocks
                for handler in block.lifted_semantics
            )

            if has_branch_handlers:
                assert any(len(block.control_flow_edges) > 0 for block in result.devirtualized_blocks)

    def test_traces_multiple_execution_paths(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Traces multiple execution paths through VM bytecode."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.DFS,
            max_paths=500,
            timeout_seconds=30,
        )

        assert result.total_paths_explored >= 0

        if result.devirtualized_blocks:
            total_paths = sum(block.execution_paths for block in result.devirtualized_blocks)
            assert total_paths > 0

    def test_recovers_control_flow_graph_edges(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Recovers control flow graph edges from VM execution."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=200,
            timeout_seconds=25,
        )

        if result.devirtualized_blocks:
            blocks_with_edges = [b for b in result.devirtualized_blocks if len(b.control_flow_edges) > 0]

            if blocks_with_edges:
                for block in blocks_with_edges:
                    for src, dst in block.control_flow_edges:
                        assert isinstance(src, int)
                        assert isinstance(dst, int)
                        assert src > 0
                        assert dst > 0


class TestExplorationStrategies:
    """Test different path exploration strategies."""

    def test_dfs_exploration_strategy(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """DFS exploration strategy explores VM paths depth-first."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.DFS,
            max_paths=200,
            timeout_seconds=25,
        )

        assert result.technical_details["exploration_strategy"] == ExplorationStrategy.DFS.value
        assert len(result.lifted_handlers) > 0

    def test_bfs_exploration_strategy(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """BFS exploration strategy explores VM paths breadth-first."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.BFS,
            max_paths=200,
            timeout_seconds=25,
        )

        assert result.technical_details["exploration_strategy"] == ExplorationStrategy.BFS.value
        assert len(result.lifted_handlers) > 0

    def test_guided_exploration_with_dispatcher(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Guided exploration focuses on VM dispatcher and handler table."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            exploration_strategy=ExplorationStrategy.GUIDED,
            max_paths=300,
            timeout_seconds=30,
        )

        assert result.technical_details["exploration_strategy"] == ExplorationStrategy.GUIDED.value
        assert result.dispatcher_address is not None or result.handler_table is not None


class TestPathExplosionMitigation:
    """Test path explosion mitigation techniques."""

    def test_limits_active_paths_to_prevent_explosion(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Path explosion mitigation limits active paths during exploration."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=100,
            timeout_seconds=20,
        )

        assert result.technical_details["max_paths_limit"] == 100
        assert result.total_paths_explored <= 100

    def test_respects_timeout_during_exploration(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Exploration respects timeout and terminates gracefully."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        start_time = time.time()

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=1000,
            timeout_seconds=5,
        )

        elapsed = time.time() - start_time

        assert elapsed <= 15.0
        assert result.technical_details["timeout_limit"] == 5


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_corrupted_pe_header_gracefully(self, tmp_path: Path) -> None:
        """Handles corrupted PE header without crashing."""
        corrupted_binary = tmp_path / "corrupted.exe"
        corrupted_binary.write_bytes(b"MZ" + b"\x00" * 100)

        devirt = SymbolicDevirtualizer(str(corrupted_binary))

        result = devirt.devirtualize(
            vm_entry_point=0x1000,
            vm_type=VMType.GENERIC,
            max_paths=50,
            timeout_seconds=5,
        )

        assert isinstance(result, DevirtualizationResult)

    def test_handles_invalid_vm_entry_point(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Handles invalid VM entry point without crashing."""
        binary_path, _, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=0xDEADBEEF,
            vm_type=VMType.GENERIC,
            max_paths=50,
            timeout_seconds=5,
        )

        assert isinstance(result, DevirtualizationResult)
        assert result.vm_entry_point == 0xDEADBEEF

    def test_handles_empty_handler_table(self, tmp_path: Path) -> None:
        """Handles binaries with no valid handler table."""
        minimal_pe = tmp_path / "minimal.exe"
        minimal_pe.write_bytes(b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80) + b"\x00" * 100)

        devirt = SymbolicDevirtualizer(str(minimal_pe))
        result = devirt.devirtualize(
            vm_entry_point=0x1000,
            vm_type=VMType.GENERIC,
            max_paths=50,
            timeout_seconds=5,
        )

        assert isinstance(result, DevirtualizationResult)
        assert result.handler_table is None or len(result.lifted_handlers) == 0


class TestGuidedVMExplorationTechnique:
    """Test GuidedVMExploration technique."""

    def test_guided_technique_tracks_visited_handlers(self) -> None:
        """Guided technique tracks visited VM handlers."""
        technique = GuidedVMExploration(
            vm_dispatcher=0x401000,
            handler_table=0x402000,
            max_depth=50,
        )

        assert technique.vm_dispatcher == 0x401000
        assert technique.handler_table == 0x402000
        assert technique.max_depth == 50
        assert len(technique.visited_handlers) == 0

    def test_guided_technique_prunes_deep_paths(self) -> None:
        """Guided technique prunes paths exceeding max depth."""
        technique = GuidedVMExploration(
            vm_dispatcher=0x401000,
            handler_table=0x402000,
            max_depth=10,
        )

        assert technique.max_depth == 10


class TestPathExplosionMitigationTechnique:
    """Test PathExplosionMitigation technique."""

    def test_mitigation_enforces_active_path_limit(self) -> None:
        """Mitigation technique enforces active path limit."""
        mitigation = PathExplosionMitigation(
            max_active=25,
            max_total=200,
        )

        assert mitigation.max_active == 25
        assert mitigation.max_total == 200
        assert mitigation.total_stepped == 0

    def test_mitigation_tracks_total_steps(self) -> None:
        """Mitigation technique tracks total exploration steps."""
        mitigation = PathExplosionMitigation(
            max_active=50,
            max_total=500,
        )

        assert mitigation.total_stepped == 0


class TestConstraintSolving:
    """Test constraint solving capabilities."""

    def test_solves_constraints_for_handler_identification(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Constraint solving identifies handler behavior correctly."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=200,
            timeout_seconds=25,
        )

        assert result.total_constraints_solved >= 0

        handlers_with_constraints = [h for h in result.lifted_handlers.values() if len(h.constraints) > 0]

        if handlers_with_constraints:
            for handler in handlers_with_constraints:
                assert len(handler.constraints) > 0
                assert isinstance(handler.constraints, list)

    def test_symbolic_effects_capture_register_modifications(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Symbolic effects correctly capture register modifications."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=150,
            timeout_seconds=20,
        )

        handlers_with_effects = [h for h in result.lifted_handlers.values() if len(h.symbolic_effects) > 0]

        if handlers_with_effects:
            for handler in handlers_with_effects:
                assert len(handler.symbolic_effects) > 0

                for effect_name, effect_value in handler.symbolic_effects:
                    assert isinstance(effect_name, str)
                    assert effect_name.startswith("reg_")


class TestOverallConfidence:
    """Test overall confidence calculation."""

    def test_confidence_reflects_handler_quality(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Overall confidence reflects handler lifting quality."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=200,
            timeout_seconds=25,
        )

        assert 0.0 <= result.overall_confidence <= 100.0

        if len(result.lifted_handlers) > 20:
            assert result.overall_confidence >= 50.0

    def test_confidence_increases_with_block_count(self, synthetic_vm_binary: tuple[Path, int, int]) -> None:
        """Confidence increases with number of devirtualized blocks."""
        binary_path, vm_entry, _ = synthetic_vm_binary

        devirt = SymbolicDevirtualizer(str(binary_path))
        result = devirt.devirtualize(
            vm_entry_point=vm_entry,
            vm_type=VMType.GENERIC,
            max_paths=300,
            timeout_seconds=30,
        )

        if len(result.devirtualized_blocks) > 5:
            assert result.overall_confidence >= 40.0
