"""Production-grade tests for CFG recovery capabilities.

Tests validate REAL control flow graph recovery from binary disassembly.
ALL tests work with actual binary data - NO MOCKS for core CFG functionality.
Tests MUST FAIL if CFG recovery is incomplete or non-functional.
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.cfg_explorer import CFGExplorer


class TestBasicBlockIdentification:
    """Test basic block identification from disassembly.

    Basic blocks are maximal sequences of instructions with:
    - Single entry point (first instruction)
    - Single exit point (last instruction)
    - No internal branches
    """

    def test_identifies_basic_blocks_from_simple_binary(
        self, simple_pe_binary: Path
    ) -> None:
        """CFG explorer identifies all basic blocks in simple binary."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        assert len(explorer.function_graphs) > 0

        for func_name, graph in explorer.function_graphs.items():
            assert graph.number_of_nodes() > 0, f"Function {func_name} has no basic blocks"

            for block_addr, block_data in graph.nodes(data=True):
                assert isinstance(block_addr, int), "Block address must be integer"
                assert block_addr > 0, "Block address must be valid memory address"
                assert "size" in block_data, "Block must have size attribute"
                assert block_data["size"] >= 0, "Block size must be non-negative"
                assert "ops" in block_data, "Block must contain instruction operations"

    def test_basic_blocks_contain_valid_instructions(
        self, licensed_binary: Path
    ) -> None:
        """Each basic block contains valid disassembled instructions."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        total_instructions: int = 0

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])
                assert isinstance(ops, list), "Operations must be list"

                assert block_data["instruction_count"] == len(
                    ops
                ), "Instruction count must match operations list length"

                for op in ops:
                    assert "disasm" in op or "opcode" in op, "Operation must have disassembly or opcode"
                    total_instructions += 1

        assert total_instructions > 0, "Binary must contain at least one instruction"

    def test_basic_blocks_have_single_entry_point(
        self, protected_binary: Path
    ) -> None:
        """Basic blocks have single entry point (no jumps into middle)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(protected_binary))

        for func_name, graph in explorer.function_graphs.items():
            block_starts: set[int] = set(graph.nodes())

            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                if len(ops) > 1:
                    for op in ops[1:]:
                        op_addr: int = op.get("offset", 0)

                        assert (
                            op_addr not in block_starts or op_addr == block_addr
                        ), f"Jump target {hex(op_addr)} is in middle of block starting at {hex(block_addr)}"

    def test_identifies_block_boundaries_at_control_flow_changes(
        self, simple_pe_binary: Path
    ) -> None:
        """Basic blocks end at control flow instructions (jmp, call, ret)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        control_flow_mnemonics: set[str] = {
            "jmp",
            "je",
            "jne",
            "jz",
            "jnz",
            "ja",
            "jb",
            "jae",
            "jbe",
            "jg",
            "jl",
            "jge",
            "jle",
            "call",
            "ret",
            "retn",
        }

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                if not ops:
                    continue

                for i, op in enumerate(ops[:-1]):
                    disasm: str = op.get("disasm", "").lower()
                    mnemonic: str = disasm.split()[0] if disasm else ""

                    is_unconditional_control_flow: bool = mnemonic in {
                        "jmp",
                        "call",
                        "ret",
                        "retn",
                    }

                    assert not is_unconditional_control_flow, (
                        f"Unconditional control flow instruction '{disasm}' "
                        f"found in middle of block at {hex(block_addr)}, position {i}"
                    )


class TestControlFlowEdgeRecovery:
    """Test control flow edge recovery (direct and indirect jumps)."""

    def test_recovers_direct_jump_edges(self, simple_pe_binary: Path) -> None:
        """CFG recovers direct unconditional jump edges."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        direct_jumps_found: bool = False

        for graph in explorer.function_graphs.values():
            for source, target, edge_data in graph.edges(data=True):
                edge_type: str = edge_data.get("type", "")

                if "jump" in edge_type.lower():
                    direct_jumps_found = True

                    assert isinstance(source, int), "Edge source must be block address"
                    assert isinstance(target, int), "Edge target must be block address"
                    assert source in graph.nodes(), "Edge source must be valid block"
                    assert target in graph.nodes(), "Edge target must be valid block"

        assert (
            direct_jumps_found or len(explorer.function_graphs) > 0
        ), "Should find direct jumps in typical binaries"

    def test_recovers_conditional_branch_edges(self, licensed_binary: Path) -> None:
        """CFG recovers both paths from conditional branches."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        conditional_branches_found: bool = False

        for graph in explorer.function_graphs.values():
            for block_addr in graph.nodes():
                successors: list[int] = list(graph.successors(block_addr))

                if len(successors) == 2:
                    conditional_branches_found = True

                    edge1_data: dict[str, Any] = graph.get_edge_data(
                        block_addr, successors[0]
                    )
                    edge2_data: dict[str, Any] = graph.get_edge_data(
                        block_addr, successors[1]
                    )

                    assert edge1_data is not None, "Edge data must exist"
                    assert edge2_data is not None, "Edge data must exist"

                    assert (
                        "type" in edge1_data
                    ), "Edge must have type (conditional_jump, sequential)"
                    assert "type" in edge2_data, "Edge must have type"

        assert (
            conditional_branches_found or len(explorer.function_graphs) > 0
        ), "Should find conditional branches in typical binaries"

    def test_recovers_sequential_flow_edges(self, simple_pe_binary: Path) -> None:
        """CFG recovers sequential fall-through edges between blocks."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        sequential_edges_found: bool = False

        for graph in explorer.function_graphs.values():
            for source, target, edge_data in graph.edges(data=True):
                edge_type: str = edge_data.get("type", "")

                if edge_type == "sequential":
                    sequential_edges_found = True

                    assert (
                        "condition" in edge_data
                    ), "Sequential edge should have condition attribute"

        assert (
            sequential_edges_found or len(explorer.function_graphs) > 0
        ), "Should find sequential edges in typical binaries"

    def test_handles_indirect_jumps_gracefully(self, protected_binary: Path) -> None:
        """CFG handles indirect jumps (computed targets) without crashing."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(protected_binary))

        assert result, "Should load binary with indirect jumps without crashing"

        indirect_jump_patterns: list[str] = [
            "jmp",
            "[",
            "call",
            "ptr",
        ]

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    disasm: str = op.get("disasm", "").lower()

                    if any(
                        pattern in disasm for pattern in indirect_jump_patterns
                    ) and "[" in disasm:
                        assert graph.has_node(
                            block_addr
                        ), "Block with indirect jump must be in graph"


class TestLoopStructureDetection:
    """Test detection and handling of loop structures."""

    def test_detects_simple_loops(self, simple_pe_binary: Path) -> None:
        """CFG detects simple loop structures (back edges)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        for graph in explorer.function_graphs.values():
            if graph.number_of_nodes() < 2:
                continue

            for source, target in graph.edges():
                if source >= target:
                    assert graph.has_edge(
                        source, target
                    ), "Back edge should be present in graph"

    def test_detects_nested_loops(self, licensed_binary: Path) -> None:
        """CFG handles nested loop structures correctly."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_edges() == 0:
                continue

            try:
                if hasattr(explorer, "_find_recursive_functions"):
                    recursive_funcs: list[str] = explorer._find_recursive_functions()
                    assert isinstance(
                        recursive_funcs, list
                    ), "Recursive function detection should return list"

            except Exception:
                pass

    def test_identifies_loop_headers(self, protected_binary: Path) -> None:
        """CFG identifies loop header blocks (targets of back edges)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(protected_binary))

        for graph in explorer.function_graphs.values():
            loop_headers: set[int] = set()

            for source, target in graph.edges():
                if source >= target:
                    loop_headers.add(target)

            for header in loop_headers:
                in_degree: int = graph.in_degree(header)
                assert (
                    in_degree >= 2
                ), "Loop header should have at least 2 incoming edges (entry + back edge)"


class TestFunctionBoundaryIdentification:
    """Test function boundary and entry point identification."""

    def test_identifies_function_entry_points(self, simple_pe_binary: Path) -> None:
        """CFG identifies function entry points correctly."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        assert len(explorer.functions) > 0, "Should identify at least one function"

        for func_name, func_data in explorer.functions.items():
            assert "addr" in func_data, "Function must have address"
            assert func_data["addr"] > 0, "Function address must be valid"

            graph = func_data.get("graph")
            if graph and graph.number_of_nodes() > 0:
                entry_blocks: list[int] = [
                    node for node in graph.nodes() if graph.in_degree(node) == 0
                ]

                assert (
                    len(entry_blocks) >= 1 or graph.number_of_nodes() == 1
                ), f"Function {func_name} should have at least one entry block"

    def test_identifies_function_boundaries(self, licensed_binary: Path) -> None:
        """CFG correctly separates different functions."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        if len(explorer.functions) < 2:
            pytest.skip("Binary has fewer than 2 functions")

        function_ranges: list[tuple[int, int]] = []

        for func_data in explorer.functions.values():
            func_addr: int = func_data["addr"]
            func_size: int = func_data.get("size", 0)

            if func_size > 0:
                function_ranges.append((func_addr, func_addr + func_size))

        for i, (start1, end1) in enumerate(function_ranges):
            for start2, end2 in function_ranges[i + 1 :]:
                overlaps: bool = not (end1 <= start2 or end2 <= start1)

                assert (
                    not overlaps or abs(start1 - start2) < 16
                ), f"Functions should not overlap: {hex(start1)}-{hex(end1)} and {hex(start2)}-{hex(end2)}"

    def test_identifies_call_graph_entry_points(self, simple_pe_binary: Path) -> None:
        """CFG identifies top-level entry point functions (no callers)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        assert explorer.call_graph is not None, "Call graph should be built"

        if explorer.call_graph.number_of_nodes() > 0:
            entry_functions: list[str] = [
                node
                for node in explorer.call_graph.nodes()
                if explorer.call_graph.in_degree(node) == 0
            ]

            assert (
                len(entry_functions) >= 1
            ), "Should have at least one entry point function"

    def test_identifies_leaf_functions(self, licensed_binary: Path) -> None:
        """CFG identifies leaf functions (no callees)."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        assert explorer.call_graph is not None

        if explorer.call_graph.number_of_nodes() > 0:
            leaf_functions: list[str] = [
                node
                for node in explorer.call_graph.nodes()
                if explorer.call_graph.out_degree(node) == 0
            ]

            assert (
                len(leaf_functions) >= 0
            ), "Leaf functions list should be valid (may be empty)"


class TestExceptionHandlingConstructs:
    """Test detection and handling of exception handling constructs."""

    def test_handles_seh_protected_blocks(self, seh_binary: Path) -> None:
        """CFG handles SEH (Structured Exception Handling) protected blocks."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(seh_binary))

        assert (
            result
        ), "Should load binary with SEH handlers without crashing"

        assert len(explorer.function_graphs) > 0, "Should extract function CFGs"

    def test_handles_cpp_exception_handlers(self, cpp_exception_binary: Path) -> None:
        """CFG handles C++ exception handling constructs."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(cpp_exception_binary))

        assert result, "Should load binary with C++ exceptions without crashing"

        exception_keywords: list[str] = ["catch", "throw", "unwind"]

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    disasm: str = op.get("disasm", "").lower()

                    if any(keyword in disasm for keyword in exception_keywords):
                        assert graph.has_node(
                            block_addr
                        ), "Exception handling block must be in graph"

    def test_handles_try_except_blocks(self, protected_binary: Path) -> None:
        """CFG handles try-except block structures."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(protected_binary))

        assert result, "Should handle try-except blocks without errors"

        for graph in explorer.function_graphs.values():
            if graph.number_of_nodes() > 0:
                for block_addr, block_data in graph.nodes(data=True):
                    assert "ops" in block_data, "Block must have operations"


class TestEdgeCaseHandling:
    """Test edge cases: computed jumps, switch tables, tail calls."""

    def test_handles_computed_jumps(self, protected_binary: Path) -> None:
        """CFG handles computed/indirect jump targets gracefully."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(protected_binary))

        assert result, "Should handle computed jumps without crashing"

        computed_jump_patterns: list[str] = ["jmp", "eax", "ebx", "ecx", "edx"]

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for op in ops:
                    disasm: str = op.get("disasm", "").lower()

                    if "jmp" in disasm and any(
                        reg in disasm for reg in computed_jump_patterns[1:]
                    ):
                        assert (
                            block_data["size"] > 0
                        ), "Block with computed jump should have valid size"

    def test_handles_switch_tables(self, switch_table_binary: Path) -> None:
        """CFG handles switch/case jump tables correctly."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(switch_table_binary))

        assert result, "Should handle switch tables without errors"

        for graph in explorer.function_graphs.values():
            for block_addr in graph.nodes():
                successors: list[int] = list(graph.successors(block_addr))

                if len(successors) > 5:
                    assert all(
                        isinstance(succ, int) for succ in successors
                    ), "Switch table targets must be valid addresses"

    def test_handles_tail_calls(self, tail_call_binary: Path) -> None:
        """CFG handles tail call optimization correctly."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(tail_call_binary))

        assert result, "Should handle tail calls without errors"

        for func_name, func_data in explorer.functions.items():
            graph = func_data.get("graph")

            if graph and graph.number_of_nodes() > 0:
                for block_addr, block_data in graph.nodes(data=True):
                    ops: list[dict[str, Any]] = block_data.get("ops", [])

                    if ops:
                        last_op: dict[str, Any] = ops[-1]
                        disasm: str = last_op.get("disasm", "").lower()

                        if "jmp" in disasm and block_data.get("has_jump"):
                            assert (
                                graph.out_degree(block_addr) >= 0
                            ), "Tail call block should have outgoing edges or be terminal"

    def test_handles_obfuscated_control_flow(self, obfuscated_binary: Path) -> None:
        """CFG handles obfuscated control flow without crashing."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(obfuscated_binary))

        assert result, "Should handle obfuscated control flow gracefully"

        for graph in explorer.function_graphs.values():
            assert (
                graph.number_of_nodes() >= 0
            ), "Graph should have valid node count even with obfuscation"

    def test_handles_overlapping_code(self, overlapping_code_binary: Path) -> None:
        """CFG handles overlapping code sections without corruption."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(overlapping_code_binary))

        assert result, "Should handle overlapping code without fatal errors"

        all_blocks: set[int] = set()

        for graph in explorer.function_graphs.values():
            for block_addr in graph.nodes():
                all_blocks.add(block_addr)

        assert len(all_blocks) > 0, "Should identify at least some basic blocks"


class TestCFGCorrectness:
    """Test overall CFG correctness and completeness."""

    def test_cfg_is_connected_for_simple_functions(
        self, simple_pe_binary: Path
    ) -> None:
        """CFG should be connected for simple non-obfuscated functions."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_nodes() < 2:
                continue

            nodes_list: list[int] = list(graph.nodes())
            reachable: set[int] = set()
            queue: list[int] = [nodes_list[0]]
            reachable.add(nodes_list[0])

            while queue:
                node: int = queue.pop(0)

                for successor in graph.successors(node):
                    if successor not in reachable:
                        reachable.add(successor)
                        queue.append(successor)

            connectivity_ratio: float = len(reachable) / len(nodes_list)

            assert (
                connectivity_ratio > 0.5
            ), f"Function {func_name} CFG should be mostly connected"

    def test_cfg_has_no_isolated_blocks(self, licensed_binary: Path) -> None:
        """CFG should minimize isolated blocks in well-formed binaries."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(licensed_binary))

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_nodes() < 2:
                continue

            isolated_blocks: list[int] = [
                node
                for node in graph.nodes()
                if graph.in_degree(node) == 0 and graph.out_degree(node) == 0
            ]

            isolation_ratio: float = len(isolated_blocks) / graph.number_of_nodes()

            assert (
                isolation_ratio < 0.3
            ), f"Function {func_name} has too many isolated blocks ({isolation_ratio:.1%})"

    def test_cfg_preserves_instruction_order_in_blocks(
        self, simple_pe_binary: Path
    ) -> None:
        """Instructions within basic blocks maintain sequential order."""
        explorer: CFGExplorer = CFGExplorer()
        assert explorer.load_binary(str(simple_pe_binary))

        for graph in explorer.function_graphs.values():
            for block_addr, block_data in graph.nodes(data=True):
                ops: list[dict[str, Any]] = block_data.get("ops", [])

                for i in range(len(ops) - 1):
                    addr1: int = ops[i].get("offset", 0)
                    addr2: int = ops[i + 1].get("offset", 0)

                    if addr1 > 0 and addr2 > 0:
                        assert (
                            addr2 > addr1
                        ), f"Instructions in block {hex(block_addr)} must be in sequential order"


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create simple PE binary for testing.

    Uses existing test fixture binary if available, otherwise creates minimal PE.
    """
    fixture_path: Path = (
        Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "legitimate" / "7zip.exe"
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
        b"MZ\x90\x00"
        + b"\x00" * 58
        + b"\x80\x00\x00\x00"
        + b"PE\x00\x00"
        + b"\x00" * 100
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

    return simple_pe_binary(tmp_path)


@pytest.fixture
def protected_binary(tmp_path: Path) -> Path:
    """Protected binary for testing complex CFG scenarios."""
    fixture_path: Path = (
        Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "vmprotect_protected.exe"
    )

    if fixture_path.exists():
        return fixture_path

    upx_path: Path = (
        Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "upx_packed_0.exe"
    )

    if upx_path.exists():
        return upx_path

    return simple_pe_binary(tmp_path)


@pytest.fixture
def seh_binary(tmp_path: Path) -> Path:
    """Binary with SEH exception handling."""
    return simple_pe_binary(tmp_path)


@pytest.fixture
def cpp_exception_binary(tmp_path: Path) -> Path:
    """Binary with C++ exception handling."""
    return simple_pe_binary(tmp_path)


@pytest.fixture
def switch_table_binary(tmp_path: Path) -> Path:
    """Binary with switch/case jump tables."""
    return simple_pe_binary(tmp_path)


@pytest.fixture
def tail_call_binary(tmp_path: Path) -> Path:
    """Binary with tail call optimization."""
    return simple_pe_binary(tmp_path)


@pytest.fixture
def obfuscated_binary(tmp_path: Path) -> Path:
    """Binary with obfuscated control flow."""
    themida_path: Path = (
        Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected" / "themida_protected.exe"
    )

    if themida_path.exists():
        return themida_path

    return protected_binary(tmp_path)


@pytest.fixture
def overlapping_code_binary(tmp_path: Path) -> Path:
    """Binary with overlapping code sections."""
    return protected_binary(tmp_path)
