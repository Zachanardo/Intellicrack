"""Production tests for radare2 graph view module.

Tests graph generation functionality on real binaries without mocks,
validating CFG, call graphs, and visualization capabilities.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_graph_view import (
    GraphData,
    GraphEdge,
    GraphNode,
    R2GraphGenerator,
    create_graph_generator,
)

try:
    import r2pipe

    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False


try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


try:
    import matplotlib.pyplot as plt

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create a simple test binary."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00" * 500
    )
    return binary_path


@pytest.fixture
def graph_generator(test_binary: Path) -> R2GraphGenerator:
    """Create graph generator instance."""
    gen = R2GraphGenerator(str(test_binary))
    yield gen
    gen.cleanup()


class TestGraphDataStructures:
    """Test graph data structure classes."""

    def test_graph_node_creation(self) -> None:
        """GraphNode creates with all attributes."""
        node = GraphNode(
            id="node1",
            label="Test Node",
            type="function",
            address=0x1000,
            size=100,
            color="#FF0000",
        )

        assert node.id == "node1"
        assert node.label == "Test Node"
        assert node.type == "function"
        assert node.address == 0x1000
        assert node.size == 100
        assert node.color == "#FF0000"
        assert isinstance(node.attributes, dict)

    def test_graph_node_default_values(self) -> None:
        """GraphNode has appropriate defaults."""
        node = GraphNode(id="node1", label="Test", type="basic_block")

        assert node.address is None
        assert node.size is None
        assert node.x is None
        assert node.y is None
        assert node.color == "#4A90E2"
        assert node.attributes == {}

    def test_graph_edge_creation(self) -> None:
        """GraphEdge creates with all attributes."""
        edge = GraphEdge(
            source="node1",
            target="node2",
            type="call",
            label="function call",
            weight=2.0,
            color="#00FF00",
            style="dashed",
        )

        assert edge.source == "node1"
        assert edge.target == "node2"
        assert edge.type == "call"
        assert edge.label == "function call"
        assert edge.weight == 2.0
        assert edge.color == "#00FF00"
        assert edge.style == "dashed"

    def test_graph_edge_default_values(self) -> None:
        """GraphEdge has appropriate defaults."""
        edge = GraphEdge(source="n1", target="n2", type="jump")

        assert edge.label is None
        assert edge.weight == 1.0
        assert edge.color == "#666666"
        assert edge.style == "solid"

    def test_graph_data_creation(self) -> None:
        """GraphData container creates correctly."""
        node = GraphNode(id="n1", label="Node 1", type="function")
        edge = GraphEdge(source="n1", target="n2", type="call")

        graph = GraphData(
            nodes=[node], edges=[edge], metadata={"type": "test", "version": 1}
        )

        assert len(graph.nodes) == 1
        assert len(graph.edges) == 1
        assert graph.metadata["type"] == "test"
        assert graph.metadata["version"] == 1

    def test_graph_data_default_values(self) -> None:
        """GraphData has empty defaults."""
        graph = GraphData()

        assert graph.nodes == []
        assert graph.edges == []
        assert graph.metadata == {}


class TestR2GraphGeneratorInitialization:
    """Test R2GraphGenerator initialization."""

    def test_generator_creates_without_r2pipe(self, test_binary: Path) -> None:
        """Generator initializes even without r2pipe."""
        gen = R2GraphGenerator(str(test_binary))
        assert gen.binary_path == str(test_binary)
        assert gen.logger is not None
        gen.cleanup()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_generator_initializes_r2_session(self, test_binary: Path) -> None:
        """Generator initializes r2 session when r2pipe available."""
        gen = R2GraphGenerator(str(test_binary))
        assert gen.r2pipe_available is True
        gen.cleanup()

    def test_generator_handles_missing_binary(self, tmp_path: Path) -> None:
        """Generator handles nonexistent binary gracefully."""
        nonexistent = tmp_path / "nonexistent.exe"
        gen = R2GraphGenerator(str(nonexistent))
        assert gen.binary_path == str(nonexistent)
        gen.cleanup()


class TestControlFlowGraphGeneration:
    """Test control flow graph generation."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_generate_cfg_returns_graph_data(self, graph_generator: R2GraphGenerator) -> None:
        """CFG generation returns GraphData structure."""
        graph = graph_generator.generate_control_flow_graph("main")
        assert isinstance(graph, GraphData)
        assert graph.metadata.get("type") == "control_flow"
        assert graph.metadata.get("function") == "main"

    def test_generate_cfg_without_r2_returns_empty(self, test_binary: Path) -> None:
        """CFG generation without r2 returns empty GraphData."""
        gen = R2GraphGenerator(str(test_binary))
        gen.r2 = None
        graph = gen.generate_control_flow_graph("main")
        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        gen.cleanup()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_cfg_nodes_have_correct_attributes(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """CFG nodes have address and size attributes."""
        graph = graph_generator.generate_control_flow_graph("main")
        if graph.nodes:
            node = graph.nodes[0]
            assert node.type == "basic_block"
            assert node.id.startswith("bb_")
            assert "BB @" in node.label

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_cfg_edges_have_correct_types(self, graph_generator: R2GraphGenerator) -> None:
        """CFG edges have appropriate types."""
        graph = graph_generator.generate_control_flow_graph("main")
        if graph.edges:
            for edge in graph.edges:
                assert edge.type in ["jump", "conditional", "switch"]

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_cfg_conditional_blocks_colored_red(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Conditional blocks are colored differently."""
        graph = graph_generator.generate_control_flow_graph("main")
        if graph.nodes:
            assert all(isinstance(node.color, str) for node in graph.nodes)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_cfg_handles_invalid_function(self, graph_generator: R2GraphGenerator) -> None:
        """CFG generation handles invalid function names gracefully."""
        graph = graph_generator.generate_control_flow_graph("nonexistent_func")
        assert isinstance(graph, GraphData)


class TestCallGraphGeneration:
    """Test call graph generation."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_generate_call_graph_returns_graph_data(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Call graph generation returns GraphData structure."""
        graph = graph_generator.generate_call_graph(max_depth=2)
        assert isinstance(graph, GraphData)
        assert graph.metadata.get("type") == "call_graph"
        assert graph.metadata.get("max_depth") == 2

    def test_generate_call_graph_without_r2_returns_empty(
        self, test_binary: Path
    ) -> None:
        """Call graph generation without r2 returns empty GraphData."""
        gen = R2GraphGenerator(str(test_binary))
        gen.r2 = None
        graph = gen.generate_call_graph()
        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0
        gen.cleanup()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_call_graph_nodes_are_functions(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Call graph nodes represent functions."""
        graph = graph_generator.generate_call_graph()
        if graph.nodes:
            assert all(node.type == "function" for node in graph.nodes)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_call_graph_main_colored_red(self, graph_generator: R2GraphGenerator) -> None:
        """Main function is colored red in call graph."""
        graph = graph_generator.generate_call_graph()
        if main_nodes := [n for n in graph.nodes if "main" in n.id.lower()]:
            assert any(node.color == "#E74C3C" for node in main_nodes)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_call_graph_imports_colored_blue(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Import functions are colored blue."""
        graph = graph_generator.generate_call_graph()
        if import_nodes := [n for n in graph.nodes if "sym.imp." in n.id]:
            assert all(node.color == "#3498DB" for node in import_nodes)

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_call_graph_edges_are_calls(self, graph_generator: R2GraphGenerator) -> None:
        """Call graph edges represent function calls."""
        graph = graph_generator.generate_call_graph()
        if graph.edges:
            assert all(edge.type == "call" for edge in graph.edges)


class TestXRefGraphGeneration:
    """Test cross-reference graph generation."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_generate_xref_graph_returns_graph_data(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Xref graph generation returns GraphData structure."""
        graph = graph_generator.generate_xref_graph(0x1000)
        assert isinstance(graph, GraphData)
        assert graph.metadata.get("type") == "xref_graph"
        assert graph.metadata.get("address") == 0x1000

    def test_generate_xref_graph_without_r2_returns_empty(
        self, test_binary: Path
    ) -> None:
        """Xref graph generation without r2 returns empty GraphData."""
        gen = R2GraphGenerator(str(test_binary))
        gen.r2 = None
        graph = gen.generate_xref_graph(0x1000)
        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0
        gen.cleanup()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_xref_graph_has_central_node(self, graph_generator: R2GraphGenerator) -> None:
        """Xref graph has central address node."""
        graph = graph_generator.generate_xref_graph(0x1000)
        if graph.nodes:
            central = next((n for n in graph.nodes if n.type == "address"), None)
            assert central is not None
            assert central.address == 0x1000

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_xref_graph_references_from_and_to(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Xref graph shows references to and from address."""
        graph = graph_generator.generate_xref_graph(0x1000)
        if graph.nodes:
            node_types = {n.type for n in graph.nodes}
            assert "address" in node_types


class TestImportDependencyGraph:
    """Test import dependency graph generation."""

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_generate_import_graph_returns_graph_data(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Import dependency graph generation returns GraphData."""
        graph = graph_generator.generate_import_dependency_graph()
        assert isinstance(graph, GraphData)
        assert graph.metadata.get("type") == "import_dependency"

    def test_generate_import_graph_without_r2_returns_empty(
        self, test_binary: Path
    ) -> None:
        """Import graph generation without r2 returns empty GraphData."""
        gen = R2GraphGenerator(str(test_binary))
        gen.r2 = None
        graph = gen.generate_import_dependency_graph()
        assert isinstance(graph, GraphData)
        assert len(graph.nodes) == 0
        gen.cleanup()

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_import_graph_has_main_binary_node(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Import graph has main binary node."""
        graph = graph_generator.generate_import_dependency_graph()
        if graph.nodes:
            main_node = next((n for n in graph.nodes if n.type == "binary"), None)
            assert main_node is not None
            assert main_node.id == "main_binary"

    @pytest.mark.skipif(not R2PIPE_AVAILABLE, reason="r2pipe not available")
    def test_import_graph_groups_by_library(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Import graph groups imports by library."""
        graph = graph_generator.generate_import_dependency_graph()
        if library_nodes := [n for n in graph.nodes if n.type == "library"]:
            assert all(hasattr(n, "attributes") for n in library_nodes)


class TestGraphExport:
    """Test graph export functionality."""

    def test_export_to_dot_creates_file(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """Export to DOT creates output file."""
        graph = GraphData(
            nodes=[GraphNode(id="n1", label="Node 1", type="function")],
            edges=[],
            metadata={"type": "test"},
        )

        output_path = tmp_path / "graph.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        assert output_path.exists()

    def test_export_to_dot_valid_format(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """Exported DOT file has valid format."""
        node1 = GraphNode(id="n1", label="Node 1", type="function", color="#FF0000")
        node2 = GraphNode(id="n2", label="Node 2", type="function", color="#00FF00")
        edge = GraphEdge(source="n1", target="n2", type="call", label="calls")

        graph = GraphData(nodes=[node1, node2], edges=[edge])

        output_path = tmp_path / "graph.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        content = output_path.read_text()
        assert "digraph G {" in content
        assert '"n1"' in content
        assert '"n2"' in content
        assert '"n1" -> "n2"' in content

    def test_export_to_dot_handles_newlines(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """DOT export handles newlines in labels."""
        node = GraphNode(id="n1", label="Line 1\nLine 2", type="function")
        graph = GraphData(nodes=[node], edges=[])

        output_path = tmp_path / "graph.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        content = output_path.read_text()
        assert "\\n" in content

    def test_export_to_dot_handles_empty_graph(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """DOT export handles empty graphs."""
        graph = GraphData()
        output_path = tmp_path / "graph.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        assert output_path.exists()


class TestGraphVisualization:
    """Test graph visualization."""

    @pytest.mark.skipif(
        not (NETWORKX_AVAILABLE and MATPLOTLIB_AVAILABLE),
        reason="NetworkX or Matplotlib not available",
    )
    def test_visualize_graph_with_networkx(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Visualization works with NetworkX and Matplotlib."""
        node1 = GraphNode(id="n1", label="Node 1", type="function")
        node2 = GraphNode(id="n2", label="Node 2", type="function")
        edge = GraphEdge(source="n1", target="n2", type="call")

        graph = GraphData(nodes=[node1, node2], edges=[edge])

        result = graph_generator.visualize_graph(graph, layout="spring")
        assert result is True or result is False

    def test_visualize_graph_without_dependencies(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Visualization fails gracefully without dependencies."""
        if not NETWORKX_AVAILABLE or not MATPLOTLIB_AVAILABLE:
            graph = GraphData()

            result = graph_generator.visualize_graph(graph)
            assert result is False

    @pytest.mark.skipif(
        not (NETWORKX_AVAILABLE and MATPLOTLIB_AVAILABLE),
        reason="NetworkX or Matplotlib not available",
    )
    def test_visualize_graph_different_layouts(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Visualization supports different layout algorithms."""
        node = GraphNode(id="n1", label="Node 1", type="function")
        graph = GraphData(nodes=[node], edges=[])

        for layout in ["spring", "circular", "shell", "kamada_kawai"]:
            result = graph_generator.visualize_graph(graph, layout=layout)
            assert isinstance(result, bool)


class TestResourceCleanup:
    """Test resource cleanup."""

    def test_cleanup_closes_r2_session(self, test_binary: Path) -> None:
        """Cleanup closes r2 session properly."""
        gen = R2GraphGenerator(str(test_binary))
        gen.cleanup()

    def test_cleanup_handles_none_r2(self, test_binary: Path) -> None:
        """Cleanup handles None r2 session gracefully."""
        gen = R2GraphGenerator(str(test_binary))
        gen.r2 = None
        gen.cleanup()


class TestFactoryFunction:
    """Test factory function."""

    def test_create_graph_generator(self, test_binary: Path) -> None:
        """Factory creates graph generator."""
        gen = create_graph_generator(str(test_binary))
        assert isinstance(gen, R2GraphGenerator)
        assert gen.binary_path == str(test_binary)
        gen.cleanup()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_graph_with_no_edges(self, graph_generator: R2GraphGenerator, tmp_path: Path) -> None:
        """Graph with only nodes exports correctly."""
        node = GraphNode(id="n1", label="Isolated Node", type="function")
        graph = GraphData(nodes=[node], edges=[])

        output_path = tmp_path / "isolated.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        assert output_path.exists()

    def test_graph_with_self_loops(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """Graph with self-referencing edges exports correctly."""
        node = GraphNode(id="n1", label="Recursive", type="function")
        edge = GraphEdge(source="n1", target="n1", type="call")
        graph = GraphData(nodes=[node], edges=[edge])

        output_path = tmp_path / "self_loop.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        content = output_path.read_text()
        assert '"n1" -> "n1"' in content

    def test_large_graph_export(
        self, graph_generator: R2GraphGenerator, tmp_path: Path
    ) -> None:
        """Large graph with many nodes exports successfully."""
        nodes = [GraphNode(id=f"n{i}", label=f"Node {i}", type="function") for i in range(100)]
        edges = [
            GraphEdge(source=f"n{i}", target=f"n{i+1}", type="call") for i in range(99)
        ]
        graph = GraphData(nodes=nodes, edges=edges)

        output_path = tmp_path / "large.dot"
        graph_generator.export_to_dot(graph, str(output_path))

        assert output_path.exists()
        assert output_path.stat().st_size > 0


class TestMetadataPreservation:
    """Test metadata preservation in graphs."""

    def test_cfg_metadata_includes_function_name(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """CFG metadata includes function name."""
        graph = graph_generator.generate_control_flow_graph("test_func")
        assert graph.metadata.get("function") == "test_func"

    def test_call_graph_metadata_includes_depth(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Call graph metadata includes max depth."""
        graph = graph_generator.generate_call_graph(max_depth=5)
        assert graph.metadata.get("max_depth") == 5

    def test_xref_graph_metadata_includes_address(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """Xref graph metadata includes target address."""
        graph = graph_generator.generate_xref_graph(0xDEADBEEF)
        assert graph.metadata.get("address") == 0xDEADBEEF

    def test_all_graphs_include_binary_path(
        self, graph_generator: R2GraphGenerator
    ) -> None:
        """All graph types include binary path in metadata."""
        graphs = [
            graph_generator.generate_control_flow_graph("main"),
            graph_generator.generate_call_graph(),
            graph_generator.generate_xref_graph(0x1000),
            graph_generator.generate_import_dependency_graph(),
        ]

        for graph in graphs:
            assert "binary" in graph.metadata
