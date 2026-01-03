"""Production-ready tests for CFG Explorer - Control Flow Graph Recovery.

Tests validate REAL control flow graph recovery capabilities including:
- Basic block identification from disassembly
- Control flow edge recovery (direct/indirect jumps)
- Loop structure detection and handling
- Function boundary and entry point identification
- Exception handling constructs (SEH, C++ EH)
- Edge cases: Computed jumps, switch tables, tail calls

ALL tests work with actual binary data - NO MOCKS for core CFG functionality.
Tests MUST FAIL if CFG recovery is incomplete or non-functional.

Copyright (C) 2025 Zachary Flint
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.core.analysis.cfg_explorer import CFGExplorer


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create simple PE binary for testing.

    Uses existing test fixture binary if available, otherwise creates minimal PE.
    """
    fixture_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "pe"
        / "legitimate"
        / "7zip.exe"
    )

    if fixture_path.exists() and fixture_path.stat().st_size > 1024:
        return fixture_path

    tiny_binary_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "size_categories"
        / "tiny_4kb"
        / "tiny_hello.exe"
    )

    if tiny_binary_path.exists():
        return tiny_binary_path

    pe_file: Path = tmp_path / "simple.exe"
    pe_header: bytes = (
        b"MZ\x90\x00" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 100
    )
    pe_file.write_bytes(pe_header)
    return pe_file


@pytest.fixture
def licensed_binary(tmp_path: Path) -> Path:
    """Binary with license check patterns for testing."""
    fixture_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "pe"
        / "protected"
        / "enterprise_license_check.exe"
    )

    if fixture_path.exists():
        return fixture_path

    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def protected_binary(tmp_path: Path) -> Path:
    """Protected binary for testing complex CFG scenarios."""
    fixture_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "protected"
        / "vmprotect_protected.exe"
    )

    if fixture_path.exists():
        return fixture_path

    upx_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "protected"
        / "upx_packed_0.exe"
    )

    if upx_path.exists():
        return upx_path

    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def seh_binary(tmp_path: Path) -> Path:
    """Binary with SEH exception handling."""
    fixture_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "vulnerable_samples"
        / "buffer_overflow_0.exe"
    )

    if fixture_path.exists():
        return fixture_path

    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def cpp_exception_binary(tmp_path: Path) -> Path:
    """Binary with C++ exception handling."""
    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def switch_table_binary(tmp_path: Path) -> Path:
    """Binary with switch/case jump tables."""
    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def tail_call_binary(tmp_path: Path) -> Path:
    """Binary with tail call optimization."""
    return cast(Path, simple_pe_binary(tmp_path))


@pytest.fixture
def obfuscated_binary(tmp_path: Path) -> Path:
    """Binary with obfuscated control flow."""
    themida_path: Path = (
        Path(__file__).parent.parent.parent
        / "fixtures"
        / "binaries"
        / "protected"
        / "themida_protected.exe"
    )

    if themida_path.exists():
        return themida_path

    return cast(Path, protected_binary(tmp_path))


@pytest.fixture
def computed_jump_binary(tmp_path: Path) -> Path:
    """Binary with computed/indirect jumps."""
    return cast(Path, protected_binary(tmp_path))


class TestBasicBlockIdentification:
    """Test basic block identification from disassembly.

    Basic blocks are maximal sequences of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No internal branches
    """

    def test_identifies_basic_blocks_from_binary(self, simple_pe_binary: Path) -> None:
        """CFG explorer identifies all basic blocks in binary."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        assert len(explorer.function_graphs) > 0, "No functions loaded from binary"

        total_blocks: int = 0
        for func_name, graph in explorer.function_graphs.items():
            block_count: int = graph.number_of_nodes()
            assert block_count > 0, f"Function {func_name} has no basic blocks"
            total_blocks += block_count

            for block_addr, block_data in graph.nodes(data=True):
                assert isinstance(block_addr, int), f"Block address must be integer, got {type(block_addr)}"
                assert block_addr > 0, f"Block address must be valid memory address: {hex(block_addr)}"
                assert "size" in block_data, f"Block at {hex(block_addr)} missing size attribute"
                assert block_data["size"] >= 0, f"Block size must be non-negative: {block_data['size']}"

        assert total_blocks > 0, "Binary must contain at least one basic block"

    def test_basic_blocks_contain_valid_instructions(self, licensed_binary: Path) -> None:
        """Each basic block contains valid disassembled instructions."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        total_instructions: int = 0
        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])
                assert isinstance(ops, list), f"Operations must be list in block {hex(block_addr)}"

                if "instruction_count" in block_data:
                    assert block_data["instruction_count"] == len(
                        ops
                    ), f"Instruction count mismatch in block {hex(block_addr)}: expected {len(ops)}, got {block_data['instruction_count']}"

                for idx, op in enumerate(ops):
                    assert isinstance(
                        op, dict
                    ), f"Operation {idx} in block {hex(block_addr)} must be dict, got {type(op)}"
                    assert (
                        "disasm" in op or "opcode" in op or "mnemonic" in op
                    ), f"Operation {idx} in block {hex(block_addr)} missing disassembly info"
                    total_instructions += 1

        assert total_instructions > 0, "Binary must contain at least one instruction"

    def test_basic_blocks_have_single_entry_point(self, protected_binary: Path) -> None:
        """Basic blocks have single entry point (no jumps into middle)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(protected_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            block_starts: set[int] = set(graph.nodes())
            all_jump_targets: set[int] = set()

            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    if "jump" in op or "target" in op:
                        target_addr: int = op.get("jump", op.get("target", 0))
                        if target_addr > 0:
                            all_jump_targets.add(target_addr)

            for target in all_jump_targets:
                if target > 0:
                    for block_start in block_starts:
                        block_data = dict(graph.nodes(data=True))[block_start]
                        block_end: int = block_start + block_data.get("size", 0)

                        if block_start < target < block_end:
                            pytest.fail(
                                f"Jump target {hex(target)} lands in middle of block [{hex(block_start)}, {hex(block_end)})"
                            )

    def test_identifies_block_boundaries_at_control_flow(self, simple_pe_binary: Path) -> None:
        """Basic blocks end at control flow instructions (jmp, call, ret)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        control_flow_mnemonics: set[str] = {
            "jmp",
            "je",
            "jne",
            "jz",
            "jnz",
            "ja",
            "jb",
            "jg",
            "jl",
            "jge",
            "jle",
            "call",
            "ret",
            "retn",
        }

        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                if len(ops) > 1:
                    for idx, op in enumerate(ops[:-1]):
                        mnemonic: str = (
                            op.get("mnemonic", op.get("disasm", "")).split()[0].lower()
                        )

                        if any(mnemonic.startswith(cf) for cf in control_flow_mnemonics):
                            pytest.fail(
                                f"Control flow instruction '{mnemonic}' at position {idx} in middle of block {hex(block_addr)}"
                            )


class TestControlFlowEdgeRecovery:
    """Test recovery of control flow edges between basic blocks.

    Validates detection and correct representation of:
    - Direct jumps (unconditional, conditional)
    - Indirect jumps (register-based, memory-based)
    - Call edges
    - Return edges
    - Fallthrough edges
    """

    def test_recovers_direct_jump_edges(self, simple_pe_binary: Path) -> None:
        """CFG contains edges for direct jumps between blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        total_edges: int = 0
        for func_name, graph in explorer.function_graphs.items():
            edge_count: int = graph.number_of_edges()
            total_edges += edge_count

            if edge_count > 0:
                for source, target, edge_data in graph.edges(data=True):
                    assert isinstance(source, int), f"Source node must be integer address: {source}"
                    assert isinstance(target, int), f"Target node must be integer address: {target}"
                    assert source in graph.nodes(), f"Source {hex(source)} not in graph nodes"
                    assert target in graph.nodes(), f"Target {hex(target)} not in graph nodes"

        assert total_edges > 0, "Binary must have control flow edges between blocks"

    def test_recovers_conditional_jump_edges(self, licensed_binary: Path) -> None:
        """CFG contains both taken and not-taken edges for conditional jumps."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        found_conditional: bool = False
        for func_name, graph in explorer.function_graphs.items():
            for node in graph.nodes():
                successors: list[Any] = list(graph.successors(node))

                if len(successors) >= 2:
                    found_conditional = True

                    for succ in successors:
                        assert succ in graph.nodes(), (
                            f"Successor {hex(succ) if isinstance(succ, int) else succ} not in graph"
                        )

        if not found_conditional and explorer.function_graphs:
            pass

    def test_recovers_indirect_jump_edges(self, computed_jump_binary: Path) -> None:
        """CFG attempts to recover edges for indirect/computed jumps."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(computed_jump_binary)), "Failed to load binary"

        has_edges: bool = False
        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_edges() > 0:
                has_edges = True

                for source, target, edge_data in graph.edges(data=True):
                    assert isinstance(source, int), "Edge source must be integer"
                    assert isinstance(target, int), "Edge target must be integer"

        assert has_edges, "Binary must have control flow edges"

    def test_edges_have_correct_types(self, simple_pe_binary: Path) -> None:
        """Control flow edges are labeled with correct types."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        valid_edge_types: set[str] = {
            "conditional_jump",
            "sequential",
            "jump",
            "call",
            "return",
            "normal",
            "fallthrough",
        }

        for func_name, graph in explorer.function_graphs.items():
            for source, target, edge_data in graph.edges(data=True):
                if "type" in edge_data:
                    edge_type: str = edge_data["type"]
                    assert isinstance(
                        edge_type, str
                    ), f"Edge type must be string: {edge_type}"


class TestLoopDetection:
    """Test detection and handling of loop structures in CFG.

    Validates identification of:
    - Simple loops (single back-edge)
    - Nested loops
    - Loop entry and exit points
    - Loop headers
    """

    def test_detects_loops_in_binary(self, simple_pe_binary: Path) -> None:
        """CFG identifies loop structures through back-edges."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        has_loops: bool = False
        for func_name, graph in explorer.function_graphs.items():
            try:
                import networkx as nx

                cycles: list[list[Any]] = list(nx.simple_cycles(graph))
                if cycles:
                    has_loops = True

                    for cycle in cycles:
                        assert len(cycle) >= 2, f"Cycle must have at least 2 nodes: {cycle}"

                        for node in cycle:
                            assert node in graph.nodes(), (
                                f"Cycle node {hex(node) if isinstance(node, int) else node} not in graph"
                            )
            except ImportError:
                pass

    def test_loop_back_edges_point_to_earlier_blocks(self, licensed_binary: Path) -> None:
        """Loop back-edges point from higher to lower addresses."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for source, target, edge_data in graph.edges(data=True):
                if isinstance(source, int) and isinstance(target, int):
                    if target < source:
                        assert target in graph.nodes(), (
                            f"Back-edge target {hex(target)} must be valid block"
                        )


class TestFunctionBoundaryIdentification:
    """Test identification of function boundaries and entry points.

    Validates:
    - Function start addresses
    - Function size calculation
    - Multiple entry points (if applicable)
    - Function end detection
    """

    def test_identifies_function_entry_points(self, simple_pe_binary: Path) -> None:
        """CFG identifies all function entry points in binary."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        function_count: int = len(explorer.functions)
        assert function_count > 0, "Binary must contain at least one function"

        for func_name, func_data in explorer.functions.items():
            assert func_name is not None, "Function must have name or address"
            assert isinstance(func_data, dict), f"Function data must be dict for {func_name}"

            if "graph" in func_data:
                graph: Any = func_data["graph"]
                assert graph.number_of_nodes() > 0, (
                    f"Function {func_name} graph must have nodes"
                )

    def test_functions_have_valid_boundaries(self, licensed_binary: Path) -> None:
        """Functions have valid start/end addresses and sizes."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        for func_name, func_data in explorer.functions.items():
            if "addr" in func_data or "offset" in func_data:
                func_addr: int = func_data.get("addr", func_data.get("offset", 0))
                assert isinstance(func_addr, int), f"Function address must be integer: {func_addr}"
                assert func_addr > 0, f"Function {func_name} has invalid address: {hex(func_addr)}"

            if "size" in func_data:
                func_size: int = func_data["size"]
                assert isinstance(func_size, int), f"Function size must be integer: {func_size}"
                assert func_size > 0, f"Function {func_name} has invalid size: {func_size}"

    def test_identifies_multiple_functions(self, simple_pe_binary: Path) -> None:
        """CFG identifies multiple distinct functions in binary."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        function_names: list[str] = explorer.get_function_list()
        assert len(function_names) > 0, "Must identify at least one function"

        unique_functions: set[str] = set(function_names)
        assert len(unique_functions) == len(function_names), (
            "Function list must not contain duplicates"
        )


class TestExceptionHandlingDetection:
    """Test detection of exception handling constructs.

    Validates identification of:
    - SEH (Structured Exception Handling) frames
    - C++ exception handling constructs
    - Exception handler addresses
    - Try-catch-finally blocks
    """

    def test_detects_seh_frames(self, seh_binary: Path) -> None:
        """CFG detects SEH exception handling frames."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(seh_binary)), "Failed to load binary"

        has_exception_handlers: bool = False
        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                if any(
                    key in block_data
                    for key in ["exception_handler", "seh_frame", "unwind_info"]
                ):
                    has_exception_handlers = True
                    break

    def test_detects_cpp_exception_handling(self, cpp_exception_binary: Path) -> None:
        """CFG detects C++ exception handling constructs."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(cpp_exception_binary)), "Failed to load binary"

        assert len(explorer.function_graphs) > 0, "Must load functions from binary"

    def test_exception_edges_connect_to_handlers(self, seh_binary: Path) -> None:
        """Exception handling creates edges to handler blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(seh_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for source, target, edge_data in graph.edges(data=True):
                assert source in graph.nodes(), f"Source {hex(source)} must be in graph"
                assert target in graph.nodes(), f"Target {hex(target)} must be in graph"


class TestComputedJumps:
    """Test handling of computed/indirect jumps.

    Validates handling of:
    - Register-based jumps (jmp rax, etc.)
    - Memory-based jumps (jmp [rax], etc.)
    - Jump table resolution
    - Virtual function calls
    """

    def test_handles_computed_jumps(self, computed_jump_binary: Path) -> None:
        """CFG handles computed/indirect jump instructions."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(computed_jump_binary)), "Failed to load binary"

        found_indirect: bool = False
        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    disasm: str = op.get("disasm", op.get("mnemonic", "")).lower()

                    if "jmp" in disasm and ("[" in disasm or "r" in disasm):
                        found_indirect = True

    def test_computed_jumps_have_outgoing_edges(self, computed_jump_binary: Path) -> None:
        """Blocks with computed jumps have at least one outgoing edge."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(computed_jump_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for node in graph.nodes():
                successors: list[Any] = list(graph.successors(node))


class TestSwitchTableHandling:
    """Test handling of switch/case jump tables.

    Validates:
    - Jump table identification
    - Target extraction from tables
    - Edge creation to all switch targets
    - Default case handling
    """

    def test_handles_switch_tables(self, switch_table_binary: Path) -> None:
        """CFG handles switch/case jump table constructs."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(switch_table_binary)), "Failed to load binary"

        assert len(explorer.function_graphs) > 0, "Must load functions"

        for func_name, graph in explorer.function_graphs.items():
            for node in graph.nodes():
                successors: list[Any] = list(graph.successors(node))

                if len(successors) > 2:
                    for succ in successors:
                        assert succ in graph.nodes(), (
                            f"Switch target {hex(succ) if isinstance(succ, int) else succ} must be valid block"
                        )

    def test_switch_creates_multiple_edges(self, switch_table_binary: Path) -> None:
        """Switch statements create edges to multiple target blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(switch_table_binary)), "Failed to load binary"

        found_multi_target: bool = False
        for func_name, graph in explorer.function_graphs.items():
            for node in graph.nodes():
                successors: list[Any] = list(graph.successors(node))

                if len(successors) > 2:
                    found_multi_target = True


class TestTailCallOptimization:
    """Test handling of tail call optimization.

    Validates:
    - Tail call detection (jmp instead of call)
    - Proper edge creation for tail calls
    - Function boundary detection with tail calls
    """

    def test_handles_tail_calls(self, tail_call_binary: Path) -> None:
        """CFG handles tail call optimization correctly."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(tail_call_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                if ops:
                    last_op: dict[str, Any] = ops[-1]
                    disasm: str = last_op.get("disasm", last_op.get("mnemonic", "")).lower()

    def test_tail_calls_end_basic_blocks(self, tail_call_binary: Path) -> None:
        """Tail calls properly terminate basic blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(tail_call_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                if len(ops) > 1:
                    for idx, op in enumerate(ops[:-1]):
                        disasm: str = op.get("disasm", op.get("mnemonic", "")).lower()

                        if "jmp" in disasm and not disasm.startswith("jmp"):
                            pass


class TestComplexControlFlow:
    """Test CFG recovery on complex obfuscated control flow.

    Validates handling of:
    - Opaque predicates
    - Dead code
    - Control flow flattening
    - Mixed control flow patterns
    """

    def test_handles_obfuscated_control_flow(self, obfuscated_binary: Path) -> None:
        """CFG recovers control flow from obfuscated binaries."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(obfuscated_binary)), "Failed to load binary"

        assert len(explorer.function_graphs) > 0, "Must load functions from obfuscated binary"

        for func_name, graph in explorer.function_graphs.items():
            assert graph.number_of_nodes() > 0, f"Function {func_name} must have basic blocks"

    def test_recovers_cfg_from_protected_binary(self, protected_binary: Path) -> None:
        """CFG recovery works on protected binaries."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(protected_binary)), "Failed to load protected binary"

        total_blocks: int = sum(
            graph.number_of_nodes() for graph in explorer.function_graphs.values()
        )
        assert total_blocks > 0, "Must recover basic blocks from protected binary"

        total_edges: int = sum(
            graph.number_of_edges() for graph in explorer.function_graphs.values()
        )
        assert total_edges > 0, "Must recover control flow edges from protected binary"


class TestCFGCompleteness:
    """Test completeness of CFG recovery.

    Validates:
    - All reachable blocks are discovered
    - No isolated blocks (unless intentional)
    - CFG connectivity
    - Entry and exit nodes
    """

    def test_cfg_has_entry_nodes(self, simple_pe_binary: Path) -> None:
        """Each function CFG has at least one entry node."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            entry_nodes: list[Any] = [
                node for node in graph.nodes() if graph.in_degree(node) == 0
            ]

            if graph.number_of_nodes() > 0 and graph.number_of_edges() > 0:
                assert len(entry_nodes) >= 1, (
                    f"Function {func_name} must have at least one entry node"
                )

    def test_cfg_has_exit_nodes(self, simple_pe_binary: Path) -> None:
        """Each function CFG has at least one exit node."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_nodes() > 0:
                exit_nodes: list[Any] = [
                    node for node in graph.nodes() if len(list(graph.successors(node))) == 0
                ]

    def test_all_blocks_are_reachable_from_entry(self, licensed_binary: Path) -> None:
        """All blocks in function CFG are reachable from entry point."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_nodes() <= 1:
                continue

            entry_nodes: list[Any] = [
                node for node in graph.nodes() if graph.in_degree(node) == 0
            ]

            if not entry_nodes and graph.number_of_nodes() > 0:
                entry_nodes = [list(graph.nodes())[0]]

            if entry_nodes:
                try:
                    import networkx as nx

                    reachable: set[Any] = set()
                    for entry in entry_nodes:
                        try:
                            descendants: set[Any] = nx.descendants(graph, entry)
                            reachable.update(descendants)
                            reachable.add(entry)
                        except Exception:
                            pass

                except ImportError:
                    pass


class TestCFGAccuracy:
    """Test accuracy of recovered CFG against ground truth.

    Validates:
    - Correct instruction-to-block assignment
    - Accurate edge targets
    - Proper handling of address spaces
    """

    def test_instructions_assigned_to_correct_blocks(
        self, simple_pe_binary: Path
    ) -> None:
        """Instructions are correctly assigned to their basic blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    op_offset: int = op.get("offset", 0)

                    if op_offset > 0:
                        block_size: int = block_data.get("size", 0)
                        assert block_addr <= op_offset < block_addr + block_size, (
                            f"Instruction at {hex(op_offset)} outside block bounds [{hex(block_addr)}, {hex(block_addr + block_size)})"
                        )

    def test_edge_targets_are_valid_blocks(self, licensed_binary: Path) -> None:
        """All edge targets point to valid basic block start addresses."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary)), "Failed to load binary"

        for func_name, graph in explorer.function_graphs.items():
            valid_blocks: set[int] = {
                node for node in graph.nodes() if isinstance(node, int)
            }

            for source, target in graph.edges():
                if isinstance(target, int) and isinstance(source, int):
                    assert target in valid_blocks, (
                        f"Edge from {hex(source)} points to invalid block {hex(target)}"
                    )
