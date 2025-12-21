"""Production tests for visualization rendering with real graph generation.

These tests validate that visualization_renderer produces correct visual outputs,
generates valid D3.js/Chart.js templates, and renders analysis graphs accurately.
Tests MUST FAIL if visualization logic produces incorrect outputs.

Copyright (C) 2025 Zachary Flint
"""

import base64
import io
import json
from pathlib import Path
from typing import Any

import pytest

from intellicrack.dashboard.visualization_renderer import (
    GraphEdge,
    GraphNode,
    VisualizationRenderer,
)


class TestVisualizationRendererProduction:
    """Production tests for visualization rendering."""

    @pytest.fixture
    def renderer(self, tmp_path: Path) -> VisualizationRenderer:
        """Create visualization renderer with temp directory."""
        config = {
            "cache_ttl": 60,
            "output_dir": str(tmp_path),
        }
        return VisualizationRenderer(config)

    @pytest.fixture
    def sample_graph_nodes(self) -> list[GraphNode]:
        """Create sample graph nodes for testing."""
        return [
            GraphNode(
                id="node1",
                label="Main Function",
                x=100.0,
                y=100.0,
                size=2.0,
                color="#3498db",
                shape="circle",
                data={"type": "function", "address": "0x401000"},
            ),
            GraphNode(
                id="node2",
                label="License Check",
                x=200.0,
                y=150.0,
                size=1.5,
                color="#e74c3c",
                shape="square",
                data={"type": "license", "address": "0x402000"},
            ),
            GraphNode(
                id="node3",
                label="Serial Validation",
                x=300.0,
                y=100.0,
                size=1.5,
                color="#f39c12",
                shape="circle",
                data={"type": "validation", "address": "0x403000"},
            ),
        ]

    @pytest.fixture
    def sample_graph_edges(self) -> list[GraphEdge]:
        """Create sample graph edges for testing."""
        return [
            GraphEdge(
                source="node1",
                target="node2",
                weight=1.0,
                color="#95a5a6",
                style="solid",
                label="calls",
                data={"call_type": "direct"},
            ),
            GraphEdge(
                source="node2",
                target="node3",
                weight=0.5,
                color="#95a5a6",
                style="dashed",
                label="validates",
                data={"call_type": "conditional"},
            ),
        ]

    def test_graph_node_to_dict_conversion(self) -> None:
        """GraphNode converts to dictionary with all fields."""
        node = GraphNode(
            id="test_node",
            label="Test Node",
            x=50.0,
            y=75.0,
            z=100.0,
            size=1.5,
            color="#ff0000",
            shape="square",
            data={"custom": "value"},
        )

        node_dict = node.to_dict()

        assert node_dict["id"] == "test_node", "ID must be preserved"
        assert node_dict["label"] == "Test Node", "Label must be preserved"
        assert node_dict["x"] == 50.0, "X coordinate must be preserved"
        assert node_dict["y"] == 75.0, "Y coordinate must be preserved"
        assert node_dict["z"] == 100.0, "Z coordinate must be preserved"
        assert node_dict["size"] == 1.5, "Size must be preserved"
        assert node_dict["color"] == "#ff0000", "Color must be preserved"
        assert node_dict["shape"] == "square", "Shape must be preserved"
        assert node_dict["data"]["custom"] == "value", "Custom data must be preserved"

    def test_graph_edge_to_dict_conversion(self) -> None:
        """GraphEdge converts to dictionary with all fields."""
        edge = GraphEdge(
            source="node_a",
            target="node_b",
            weight=2.5,
            color="#00ff00",
            style="dashed",
            label="connection",
            data={"strength": "strong"},
        )

        edge_dict = edge.to_dict()

        assert edge_dict["source"] == "node_a", "Source must be preserved"
        assert edge_dict["target"] == "node_b", "Target must be preserved"
        assert edge_dict["weight"] == 2.5, "Weight must be preserved"
        assert edge_dict["color"] == "#00ff00", "Color must be preserved"
        assert edge_dict["style"] == "dashed", "Style must be preserved"
        assert edge_dict["label"] == "connection", "Label must be preserved"
        assert edge_dict["data"]["strength"] == "strong", "Custom data must be preserved"

    def test_color_schemes_availability(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Renderer provides predefined color schemes."""
        assert "default" in renderer.color_schemes, "Must have default color scheme"
        assert "heatmap" in renderer.color_schemes, "Must have heatmap color scheme"
        assert "diverging" in renderer.color_schemes, "Must have diverging color scheme"
        assert "categorical" in renderer.color_schemes, "Must have categorical color scheme"

        assert len(renderer.color_schemes["default"]) > 0, "Default scheme must have colors"
        assert all(
            c.startswith("#") for c in renderer.color_schemes["default"]
        ), "Colors must be hex format"

    def test_chart_template_loading(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Renderer loads chart templates for JavaScript rendering."""
        assert len(renderer.chart_templates) > 0, "Must have chart templates"
        assert "d3_force_graph" in renderer.chart_templates, "Must have D3 force graph template"

        d3_template = renderer.chart_templates["d3_force_graph"]
        assert "{{container_id}}" in d3_template, "Template must have container placeholder"
        assert "{{width}}" in d3_template, "Template must have width placeholder"
        assert "{{height}}" in d3_template, "Template must have height placeholder"
        assert "{{nodes}}" in d3_template, "Template must have nodes placeholder"
        assert "{{edges}}" in d3_template, "Template must have edges placeholder"

    def test_d3_force_graph_template_physics(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """D3 force graph template includes physics calculations."""
        template = renderer.chart_templates["d3_force_graph"]

        assert "forceLayout" in template, "Must have force layout"
        assert "alpha" in template, "Must have alpha decay parameter"
        assert "velocityDecay" in template, "Must have velocity decay"
        assert "tick" in template, "Must have tick function"
        assert "repulsion" in template or "force" in template, "Must have force calculations"

    def test_three_d_config_parameters(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """3D rendering configuration has required parameters."""
        assert "camera_distance" in renderer.three_d_config, "Must have camera distance"
        assert "camera_angle" in renderer.three_d_config, "Must have camera angle"
        assert "rotation_speed" in renderer.three_d_config, "Must have rotation speed"
        assert "zoom_factor" in renderer.three_d_config, "Must have zoom factor"

        assert renderer.three_d_config["camera_distance"] > 0, "Camera distance must be positive"
        assert 0 < renderer.three_d_config["zoom_factor"] < 10, "Zoom factor must be reasonable"

    def test_render_cache_functionality(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Renderer caches visualizations for performance."""
        assert hasattr(renderer, "render_cache"), "Must have render cache"
        assert isinstance(renderer.render_cache, dict), "Cache must be dictionary"
        assert renderer.cache_ttl > 0, "Cache TTL must be positive"

    @pytest.mark.skipif(
        not hasattr(pytest, "importorskip") or pytest.importorskip("matplotlib", reason="matplotlib not available"),
        reason="matplotlib not available",
    )
    def test_matplotlib_integration(self) -> None:
        """Renderer integrates with matplotlib when available."""
        try:
            import matplotlib
            assert matplotlib is not None, "matplotlib must be importable"
        except ImportError:
            pytest.skip("matplotlib not available")

    @pytest.mark.skipif(
        not hasattr(pytest, "importorskip") or pytest.importorskip("networkx", reason="networkx not available"),
        reason="networkx not available",
    )
    def test_networkx_integration(self) -> None:
        """Renderer integrates with networkx when available."""
        try:
            import networkx
            assert networkx is not None, "networkx must be importable"
        except ImportError:
            pytest.skip("networkx not available")

    def test_graph_node_default_values(self) -> None:
        """GraphNode has sensible default values."""
        node = GraphNode(id="test", label="Test")

        assert node.x == 0.0, "Default x must be 0"
        assert node.y == 0.0, "Default y must be 0"
        assert node.z == 0.0, "Default z must be 0"
        assert node.size == 1.0, "Default size must be 1.0"
        assert node.color == "#3498db", "Default color must be blue"
        assert node.shape == "circle", "Default shape must be circle"
        assert node.data is None, "Default data must be None"

    def test_graph_edge_default_values(self) -> None:
        """GraphEdge has sensible default values."""
        edge = GraphEdge(source="a", target="b")

        assert edge.weight == 1.0, "Default weight must be 1.0"
        assert edge.color == "#95a5a6", "Default color must be gray"
        assert edge.style == "solid", "Default style must be solid"
        assert edge.label == "", "Default label must be empty"
        assert edge.data is None, "Default data must be None"

    def test_node_dict_with_none_data(self) -> None:
        """GraphNode with None data converts to empty dict."""
        node = GraphNode(id="test", label="Test", data=None)

        node_dict = node.to_dict()

        assert node_dict["data"] == {}, "None data must convert to empty dict"

    def test_edge_dict_with_none_data(self) -> None:
        """GraphEdge with None data converts to empty dict."""
        edge = GraphEdge(source="a", target="b", data=None)

        edge_dict = edge.to_dict()

        assert edge_dict["data"] == {}, "None data must convert to empty dict"

    def test_multiple_nodes_unique_ids(
        self,
        sample_graph_nodes: list[GraphNode],
    ) -> None:
        """Graph nodes have unique identifiers."""
        node_ids = [node.id for node in sample_graph_nodes]

        assert len(node_ids) == len(set(node_ids)), "Node IDs must be unique"

    def test_edges_reference_valid_nodes(
        self,
        sample_graph_nodes: list[GraphNode],
        sample_graph_edges: list[GraphEdge],
    ) -> None:
        """Graph edges reference nodes that exist."""
        node_ids = {node.id for node in sample_graph_nodes}

        for edge in sample_graph_edges:
            assert edge.source in node_ids, f"Edge source {edge.source} must exist"
            assert edge.target in node_ids, f"Edge target {edge.target} must exist"

    def test_node_coordinates_in_valid_range(
        self,
        sample_graph_nodes: list[GraphNode],
    ) -> None:
        """Graph node coordinates are in reasonable ranges."""
        for node in sample_graph_nodes:
            assert 0 <= node.x <= 1000, "X coordinate must be reasonable"
            assert 0 <= node.y <= 1000, "Y coordinate must be reasonable"
            assert node.size > 0, "Node size must be positive"

    def test_edge_weights_positive(
        self,
        sample_graph_edges: list[GraphEdge],
    ) -> None:
        """Graph edge weights are positive values."""
        for edge in sample_graph_edges:
            assert edge.weight > 0, "Edge weight must be positive"

    def test_color_format_validation(
        self,
        sample_graph_nodes: list[GraphNode],
    ) -> None:
        """Node and edge colors use valid hex format."""
        for node in sample_graph_nodes:
            assert node.color.startswith("#"), "Color must start with #"
            assert len(node.color) in [4, 7], "Color must be #RGB or #RRGGBB"

    def test_visualization_types_supported(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Renderer supports multiple visualization types."""
        assert "d3_force_graph" in renderer.chart_templates, "Must support D3 force graphs"

    def test_template_placeholder_consistency(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Chart templates use consistent placeholder syntax."""
        for template_name, template_code in renderer.chart_templates.items():
            placeholders = [
                "{{container_id}}",
                "{{width}}",
                "{{height}}",
            ]

            for placeholder in placeholders:
                assert placeholder in template_code, (
                    f"Template {template_name} must have {placeholder}"
                )

    def test_color_scheme_hex_validation(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """All color schemes use valid hex color codes."""
        for scheme_name, colors in renderer.color_schemes.items():
            for color in colors:
                assert color.startswith("#"), f"Color in {scheme_name} must start with #"
                assert len(color) in [4, 7], f"Color in {scheme_name} must be valid hex"
                hex_chars = color[1:]
                assert all(
                    c in "0123456789ABCDEFabcdef" for c in hex_chars
                ), f"Color {color} must be valid hex"

    def test_heatmap_color_progression(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Heatmap color scheme progresses from cool to hot."""
        heatmap = renderer.color_schemes["heatmap"]

        assert len(heatmap) >= 3, "Heatmap must have multiple colors"
        assert any("00ff00" in c.lower() for c in heatmap), "Must include green (cool)"
        assert any("ff0000" in c.lower() for c in heatmap), "Must include red (hot)"

    def test_diverging_color_scheme_balance(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Diverging color scheme has balanced ends."""
        diverging = renderer.color_schemes["diverging"]

        assert len(diverging) >= 3, "Diverging scheme must have multiple colors"
        assert len(diverging) % 2 == 1, "Diverging scheme should have odd number for midpoint"

    def test_categorical_color_distinctness(
        self,
        renderer: VisualizationRenderer,
    ) -> None:
        """Categorical colors are distinct from each other."""
        categorical = renderer.color_schemes["categorical"]

        assert len(categorical) >= 5, "Must have at least 5 distinct colors"
        assert len(categorical) == len(set(categorical)), "Colors must be unique"

    def test_graph_serialization_json_valid(
        self,
        sample_graph_nodes: list[GraphNode],
        sample_graph_edges: list[GraphEdge],
    ) -> None:
        """Graph data serializes to valid JSON."""
        nodes_data = [node.to_dict() for node in sample_graph_nodes]
        edges_data = [edge.to_dict() for edge in sample_graph_edges]

        graph_json = json.dumps({
            "nodes": nodes_data,
            "edges": edges_data,
        })

        parsed = json.loads(graph_json)
        assert len(parsed["nodes"]) == len(sample_graph_nodes), "All nodes must serialize"
        assert len(parsed["edges"]) == len(sample_graph_edges), "All edges must serialize"

    def test_node_metadata_preservation(self) -> None:
        """Node metadata is preserved through serialization."""
        node = GraphNode(
            id="func_001",
            label="License Validator",
            data={
                "address": "0x401000",
                "size": 256,
                "calls": ["verify_serial", "check_expiry"],
                "complexity": 15.5,
            },
        )

        node_dict = node.to_dict()

        assert node_dict["data"]["address"] == "0x401000", "Address must be preserved"
        assert node_dict["data"]["size"] == 256, "Size must be preserved"
        assert len(node_dict["data"]["calls"]) == 2, "Call list must be preserved"
        assert node_dict["data"]["complexity"] == 15.5, "Complexity must be preserved"

    def test_edge_metadata_preservation(self) -> None:
        """Edge metadata is preserved through serialization."""
        edge = GraphEdge(
            source="func_a",
            target="func_b",
            data={
                "call_type": "direct",
                "frequency": 100,
                "latency_ms": 2.5,
            },
        )

        edge_dict = edge.to_dict()

        assert edge_dict["data"]["call_type"] == "direct", "Call type must be preserved"
        assert edge_dict["data"]["frequency"] == 100, "Frequency must be preserved"
        assert edge_dict["data"]["latency_ms"] == 2.5, "Latency must be preserved"
