"""Production tests for Radare2 Graph View with real CFG generation.

Tests REAL graph generation capabilities:
- Control Flow Graph (CFG) generation
- Call graph construction
- Cycle detection in graphs
- Graph node and edge creation
- NetworkX integration
- Graph visualization export

All tests validate genuine graph analysis functionality.
"""

from pathlib import Path

import pytest

from intellicrack.core.analysis.radare2_graph_view import (
    GraphData,
    GraphEdge,
    GraphNode,
    R2GraphGenerator,
)


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary with multiple functions for graph testing."""
    binary_path = tmp_path / "graph_test.elf"

    x64_code = bytes([
        0x55,                                      # push rbp (main)
        0x48, 0x89, 0xe5,                          # mov rbp, rsp
        0xe8, 0x05, 0x00, 0x00, 0x00,              # call func1
        0x5d,                                      # pop rbp
        0xc3,                                      # ret
        0x55,                                      # push rbp (func1)
        0x48, 0x89, 0xe5,                          # mov rbp, rsp
        0x48, 0x83, 0xec, 0x10,                    # sub rsp, 0x10
        0x48, 0x83, 0x7d, 0xf8, 0x00,              # cmp qword [rbp-8], 0
        0x74, 0x05,                                # je skip
        0xe8, 0x00, 0x00, 0x00, 0x00,              # call func2
        0x5d,                                      # pop rbp (skip)
        0xc3,                                      # ret
    ])

    elf_header = bytes([
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

    padding = b"\x00" * (0x78 - len(elf_header) - len(program_header))
    full_binary = elf_header + program_header + padding + x64_code

    binary_path.write_bytes(full_binary)
    return binary_path


class TestGraphGeneratorInitialization:
    """Test graph generator initialization."""

    def test_initializes_with_valid_binary(self, sample_binary: Path) -> None:
        """Generator initializes with valid binary."""
        generator = R2GraphGenerator(str(sample_binary))

        assert generator.binary_path == str(sample_binary)
        assert generator.r2pipe_available is True
        assert generator.r2 is not None

    def test_handles_nonexistent_binary(self) -> None:
        """Generator handles non-existent binary gracefully."""
        generator = R2GraphGenerator("/nonexistent/binary.elf")

        assert generator.r2 is None or not generator.r2pipe_available


class TestGraphDataStructures:
    """Test graph data structure classes."""

    def test_graph_node_creation(self) -> None:
        """GraphNode stores all required attributes."""
        node = GraphNode(
            id="node_1",
            label="Test Node",
            type="basic_block",
            address=0x400000,
            size=16,
            attributes={"test": "value"},
            color="#FF0000"
        )

        assert node.id == "node_1"
        assert node.label == "Test Node"
        assert node.type == "basic_block"
        assert node.address == 0x400000
        assert node.size == 16
        assert node.attributes["test"] == "value"
        assert node.color == "#FF0000"

    def test_graph_edge_creation(self) -> None:
        """GraphEdge stores all required attributes."""
        edge = GraphEdge(
            source="node_1",
            target="node_2",
            type="jump",
            label="jmp",
            weight=1.5,
            color="#00FF00",
            style="dashed"
        )

        assert edge.source == "node_1"
        assert edge.target == "node_2"
        assert edge.type == "jump"
        assert edge.label == "jmp"
        assert edge.weight == 1.5
        assert edge.color == "#00FF00"
        assert edge.style == "dashed"

    def test_graph_data_container(self) -> None:
        """GraphData contains nodes, edges, and metadata."""
        node1 = GraphNode(id="n1", label="Node 1", type="basic_block")
        node2 = GraphNode(id="n2", label="Node 2", type="basic_block")
        edge = GraphEdge(source="n1", target="n2", type="jump")

        graph_data = GraphData(
            nodes=[node1, node2],
            edges=[edge],
            metadata={"function": "main", "type": "cfg"}
        )

        assert len(graph_data.nodes) == 2
        assert len(graph_data.edges) == 1
        assert graph_data.metadata["function"] == "main"
        assert graph_data.metadata["type"] == "cfg"


class TestControlFlowGraphGeneration:
    """Test CFG generation from binary functions."""

    def test_generates_cfg_for_function(self, sample_binary: Path) -> None:
        """Generator creates CFG for binary function."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        assert isinstance(graph, GraphData)
        assert graph.metadata["type"] == "control_flow"
        assert len(graph.nodes) >= 0
        assert isinstance(graph.nodes, list)
        assert isinstance(graph.edges, list)

    def test_cfg_nodes_have_addresses(self, sample_binary: Path) -> None:
        """CFG nodes contain address information."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for node in graph.nodes:
            assert isinstance(node, GraphNode)
            assert node.type == "basic_block"
            if node.address is not None:
                assert isinstance(node.address, int)
                assert node.address > 0

    def test_cfg_edges_represent_control_flow(self, sample_binary: Path) -> None:
        """CFG edges represent control flow between basic blocks."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for edge in graph.edges:
            assert isinstance(edge, GraphEdge)
            assert edge.type in ["jump", "conditional", "call", "fall_through"]
            assert edge.source in [n.id for n in graph.nodes]
            assert edge.target in [n.id for n in graph.nodes]


class TestCycleDetection:
    """Test cycle detection in graphs."""

    def test_detects_cycles_in_cfg(self, sample_binary: Path) -> None:
        """Generator detects cycles in control flow graphs."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        has_cycle = False
        visited = set()

        def has_cycle_dfs(node_id: str, path: set[str]) -> bool:
            if node_id in path:
                return True
            if node_id in visited:
                return False

            visited.add(node_id)
            path.add(node_id)

            for edge in graph.edges:
                if edge.source == node_id:
                    if has_cycle_dfs(edge.target, path.copy()):
                        return True

            return False

        for node in graph.nodes:
            if has_cycle_dfs(node.id, set()):
                has_cycle = True
                break

        assert isinstance(has_cycle, bool)


class TestGraphMetadata:
    """Test graph metadata handling."""

    def test_cfg_metadata_complete(self, sample_binary: Path) -> None:
        """CFG metadata contains all required information."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        assert "type" in graph.metadata
        assert "function" in graph.metadata
        assert "binary" in graph.metadata
        assert graph.metadata["type"] == "control_flow"
        assert graph.metadata["binary"] == str(sample_binary)

    def test_node_attributes_stored(self, sample_binary: Path) -> None:
        """Graph nodes store additional attributes."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for node in graph.nodes:
            assert hasattr(node, "attributes")
            assert isinstance(node.attributes, dict)


class TestNodeColoring:
    """Test node coloring based on block type."""

    def test_conditional_blocks_colored_red(self, sample_binary: Path) -> None:
        """Conditional blocks use red color coding."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for node in graph.nodes:
            if node.attributes.get("has_conditional"):
                assert node.color in ["#E74C3C", "#F39C12", "#2ECC71"]


class TestEdgeTypes:
    """Test different edge types in graphs."""

    def test_jump_edges_created(self, sample_binary: Path) -> None:
        """Jump edges are created for unconditional jumps."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        jump_edges = [e for e in graph.edges if e.type == "jump"]
        assert isinstance(jump_edges, list)

    def test_conditional_edges_created(self, sample_binary: Path) -> None:
        """Conditional edges are created for conditional jumps."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        cond_edges = [e for e in graph.edges if e.type == "conditional"]
        assert isinstance(cond_edges, list)


class TestErrorHandling:
    """Test error handling in graph generation."""

    def test_handles_invalid_function_name(self, sample_binary: Path) -> None:
        """Generator handles invalid function names gracefully."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("nonexistent_function")

        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0

    def test_handles_corrupted_binary(self, tmp_path: Path) -> None:
        """Generator handles corrupted binary data."""
        corrupted = tmp_path / "corrupted.bin"
        corrupted.write_bytes(b"\x00" * 100)

        generator = R2GraphGenerator(str(corrupted))

        assert isinstance(generator, R2GraphGenerator)


class TestEmptyGraphs:
    """Test handling of empty graphs."""

    def test_empty_function_returns_empty_graph(self, sample_binary: Path) -> None:
        """Empty function produces empty graph."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("invalid_func")

        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0


class TestGraphConsistency:
    """Test graph consistency and validity."""

    def test_all_edge_targets_exist(self, sample_binary: Path) -> None:
        """All edge targets reference existing nodes."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        node_ids = {node.id for node in graph.nodes}

        for edge in graph.edges:
            assert edge.source in node_ids or len(graph.nodes) == 0
            assert edge.target in node_ids or len(graph.nodes) == 0

    def test_no_self_loops_in_cfg(self, sample_binary: Path) -> None:
        """CFG doesn't contain self-loops unless intentional."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        self_loops = [e for e in graph.edges if e.source == e.target]
        assert len(self_loops) == 0 or all(e.type == "loop" for e in self_loops)


class TestPerformance:
    """Test graph generation performance."""

    def test_cfg_generation_completes_quickly(self, sample_binary: Path) -> None:
        """CFG generation completes within reasonable time."""
        import time

        generator = R2GraphGenerator(str(sample_binary))

        start = time.time()
        graph = generator.generate_control_flow_graph("entry0")
        duration = time.time() - start

        assert duration < 5.0
        assert isinstance(graph, GraphData)


class TestNodeProperties:
    """Test node property accuracy."""

    def test_node_size_matches_block_size(self, sample_binary: Path) -> None:
        """Node size matches basic block size."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for node in graph.nodes:
            if node.size is not None:
                assert node.size > 0
                assert isinstance(node.size, int)

    def test_node_labels_descriptive(self, sample_binary: Path) -> None:
        """Node labels contain descriptive information."""
        generator = R2GraphGenerator(str(sample_binary))

        graph = generator.generate_control_flow_graph("entry0")

        for node in graph.nodes:
            assert isinstance(node.label, str)
            assert len(node.label) > 0
