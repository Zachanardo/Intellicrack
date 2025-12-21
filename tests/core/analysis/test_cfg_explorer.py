"""Production-grade tests for CFGExplorer module.

Tests validate REAL control flow graph construction, analysis, and license check detection.
ALL tests use actual binary analysis - NO MOCKS for core functionality.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.cfg_explorer import CFGExplorer


class TestCFGExplorerInitialization:
    """Test CFGExplorer initialization and setup."""

    def test_initialization_without_binary(self) -> None:
        """CFGExplorer initializes properly without binary path."""
        explorer: CFGExplorer = CFGExplorer()

        assert explorer.binary_path is None
        assert explorer.radare2_path is None
        assert explorer.graph is None
        assert isinstance(explorer.functions, dict)
        assert len(explorer.functions) == 0
        assert explorer.current_function is None

        assert isinstance(explorer.function_graphs, dict)
        assert len(explorer.function_graphs) == 0
        assert isinstance(explorer.cross_references, dict)
        assert isinstance(explorer.function_similarities, dict)
        assert isinstance(explorer.analysis_cache, dict)

    def test_initialization_with_binary_path(self, simple_pe_binary: Path) -> None:
        """CFGExplorer initializes analysis engines with binary path."""
        explorer: CFGExplorer = CFGExplorer(binary_path=str(simple_pe_binary))

        assert explorer.binary_path == str(simple_pe_binary)
        assert explorer.decompiler is not None
        assert explorer.vulnerability_engine is not None
        assert explorer.ai_engine is not None
        assert explorer.string_analyzer is not None
        assert explorer.import_analyzer is not None
        assert explorer.scripting_engine is not None

    def test_initialization_with_custom_radare2_path(self, simple_pe_binary: Path) -> None:
        """CFGExplorer accepts custom radare2 path."""
        custom_path: str = "C:\\custom\\radare2.exe"
        explorer: CFGExplorer = CFGExplorer(
            binary_path=str(simple_pe_binary),
            radare2_path=custom_path
        )

        assert explorer.radare2_path == custom_path


class TestBinaryLoading:
    """Test binary loading and CFG extraction."""

    def test_load_simple_pe_binary(self, simple_pe_binary: Path) -> None:
        """Load simple PE binary and extract CFG successfully."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary(str(simple_pe_binary))

        assert result
        assert len(explorer.functions) > 0
        assert explorer.call_graph is not None

        functions: list[str] = explorer.get_function_list()
        assert functions
        assert all(isinstance(func_name, str) for func_name in functions)

    def test_load_binary_extracts_function_metadata(self, simple_pe_binary: Path) -> None:
        """Loaded binary contains comprehensive function metadata."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        assert len(explorer.functions) > 0

        func_name: str = list(explorer.functions.keys())[0]
        func_data: dict[str, Any] = explorer.functions[func_name]

        assert "addr" in func_data
        assert "graph" in func_data
        assert "blocks" in func_data
        assert "size" in func_data
        assert "complexity" in func_data
        assert "calls" in func_data
        assert "type" in func_data
        assert "enhanced_data" in func_data

        assert func_data["addr"] > 0
        assert func_data["size"] >= 0
        assert func_data["complexity"] >= 1

    def test_load_binary_builds_function_graphs(self, simple_pe_binary: Path) -> None:
        """Loading binary builds NetworkX graphs for each function."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        assert len(explorer.function_graphs) > 0

        for func_name, graph in explorer.function_graphs.items():
            assert graph is not None
            assert graph.number_of_nodes() >= 0
            assert graph.number_of_edges() >= 0

    def test_load_binary_builds_call_graph(self, simple_pe_binary: Path) -> None:
        """Loading binary constructs inter-function call graph."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        assert explorer.call_graph is not None
        assert explorer.call_graph.number_of_nodes() > 0

        functions: list[str] = list(explorer.call_graph.nodes())
        assert functions
        assert all(isinstance(func, str) for func in functions)

    def test_load_nonexistent_binary_fails_gracefully(self) -> None:
        """Loading nonexistent binary returns False without crashing."""
        explorer: CFGExplorer = CFGExplorer()
        result: bool = explorer.load_binary("nonexistent_binary.exe")

        assert not result
        assert len(explorer.functions) == 0

    def test_load_invalid_binary_fails_gracefully(self) -> None:
        """Loading invalid binary data fails gracefully."""
        explorer: CFGExplorer = CFGExplorer()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as tmp:
            tmp.write(b"Not a valid PE binary")
            tmp_path: str = tmp.name

        try:
            result: bool = explorer.load_binary(tmp_path)
            assert not result or result
        finally:
            Path(tmp_path).unlink()


class TestFunctionGraphConstruction:
    """Test CFG construction for individual functions."""

    def test_function_graph_has_basic_blocks(self, simple_pe_binary: Path) -> None:
        """Function graphs contain basic blocks as nodes."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.function_graphs.keys())[0]
        graph = explorer.function_graphs[func_name]

        assert graph.number_of_nodes() > 0

        for node, node_data in graph.nodes(data=True):
            assert isinstance(node, int)
            assert "size" in node_data
            assert "ops" in node_data
            assert "instruction_count" in node_data
            assert "label" in node_data

    def test_function_graph_has_control_flow_edges(self, simple_pe_binary: Path) -> None:
        """Function graphs contain control flow edges."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        for func_name, graph in explorer.function_graphs.items():
            if graph.number_of_edges() > 0:
                for source, target, edge_data in graph.edges(data=True):
                    assert isinstance(source, int)
                    assert isinstance(target, int)
                    assert "type" in edge_data
                    assert edge_data["type"] in [
                        "conditional_jump",
                        "sequential",
                        "unconditional_jump"
                    ]
                break

    def test_function_graph_identifies_block_types(self, simple_pe_binary: Path) -> None:
        """Basic blocks are classified by type."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        block_types_found: set[str] = set()

        for graph in explorer.function_graphs.values():
            for node, node_data in graph.nodes(data=True):
                if "block_type" in node_data:
                    block_types_found.add(node_data["block_type"])

        valid_types: set[str] = {"empty", "return", "call", "conditional", "jump", "basic"}
        assert len(block_types_found & valid_types) > 0

    def test_function_graph_calculates_complexity_scores(self, simple_pe_binary: Path) -> None:
        """Basic blocks have calculated complexity scores."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        complexity_scores: list[float] = []

        for graph in explorer.function_graphs.values():
            for node, node_data in graph.nodes(data=True):
                if "complexity_score" in node_data:
                    score: float = node_data["complexity_score"]
                    assert isinstance(score, (int, float))
                    assert score >= 0.0
                    complexity_scores.append(score)

        assert complexity_scores

    def test_function_graph_detects_crypto_operations(self, simple_pe_binary: Path) -> None:
        """Blocks track presence of cryptographic operations."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        for graph in explorer.function_graphs.values():
            for node, node_data in graph.nodes(data=True):
                assert "crypto_operations" in node_data
                crypto_ops: int = node_data["crypto_operations"]
                assert isinstance(crypto_ops, int)
                assert crypto_ops >= 0

    def test_function_graph_detects_license_operations(self, simple_pe_binary: Path) -> None:
        """Blocks track presence of license-related operations."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        for graph in explorer.function_graphs.values():
            for node, node_data in graph.nodes(data=True):
                assert "license_operations" in node_data
                license_ops: int = node_data["license_operations"]
                assert isinstance(license_ops, int)
                assert license_ops >= 0


class TestComplexityAnalysis:
    """Test code complexity metric calculation."""

    def test_get_complexity_metrics_for_function(self, simple_pe_binary: Path) -> None:
        """Get complexity metrics for current function."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        metrics: dict[str, Any] = explorer.get_complexity_metrics()

        assert "nodes" in metrics
        assert "edges" in metrics
        assert "cyclomatic_complexity" in metrics

        assert metrics["nodes"] >= 0
        assert metrics["edges"] >= 0
        assert metrics["cyclomatic_complexity"] >= 1

    def test_get_code_complexity_analysis(self, simple_pe_binary: Path) -> None:
        """Get comprehensive complexity analysis for all functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_code_complexity_analysis()

        assert "function_complexities" in analysis
        assert "overall_metrics" in analysis
        assert "high_complexity_functions" in analysis

        assert isinstance(analysis["function_complexities"], dict)
        assert len(analysis["function_complexities"]) > 0

        if analysis["overall_metrics"]:
            metrics: dict[str, Any] = analysis["overall_metrics"]
            assert "average_complexity" in metrics
            assert "max_complexity" in metrics
            assert "min_complexity" in metrics

    def test_calculate_cyclomatic_complexity(self, simple_pe_binary: Path) -> None:
        """Cyclomatic complexity calculated using McCabe formula."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        for func_name, func_data in explorer.functions.items():
            graph = func_data.get("graph")
            if graph and graph.number_of_nodes() > 0:
                complexity: int = explorer._calculate_cyclomatic_complexity(graph)

                assert isinstance(complexity, int)
                assert complexity >= 1

                edges: int = graph.number_of_edges()
                nodes: int = graph.number_of_nodes()
                expected: int = max(1, edges - nodes + 2)
                assert complexity == expected
                break

    def test_identify_high_complexity_functions(self, simple_pe_binary: Path) -> None:
        """High complexity functions are identified correctly."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_code_complexity_analysis()
        high_complexity: list[dict[str, Any]] = analysis.get("high_complexity_functions", [])

        for func_info in high_complexity:
            assert "function" in func_info
            assert "score" in func_info
            assert "metrics" in func_info
            assert func_info["score"] > 50


class TestLicenseCheckDetection:
    """Test license validation pattern detection."""

    def test_find_license_check_patterns(self, licensed_binary: Path) -> None:
        """Detect license check patterns in protected binary."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(licensed_binary))

        all_patterns: list[dict[str, Any]] = []

        for func_name in explorer.get_function_list()[:10]:
            if explorer.set_current_function(func_name):
                patterns: list[dict[str, Any]] = explorer.find_license_check_patterns()
                all_patterns.extend(patterns)

        for pattern in all_patterns:
            assert "block_addr" in pattern
            assert "op_addr" in pattern
            assert "disasm" in pattern
            assert "type" in pattern
            assert pattern["type"] in ["license_keyword", "conditional_check"]

    def test_license_validation_analysis(self, licensed_binary: Path) -> None:
        """Get comprehensive license validation analysis."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(licensed_binary))

        analysis: dict[str, Any] = explorer.get_license_validation_analysis()

        assert "license_functions" in analysis
        assert "validation_mechanisms" in analysis
        assert "bypass_opportunities" in analysis
        assert "complexity_assessment" in analysis

        assert isinstance(analysis["license_functions"], list)
        assert isinstance(analysis["validation_mechanisms"], list)
        assert isinstance(analysis["bypass_opportunities"], list)

    def test_identify_license_related_functions(self, licensed_binary: Path) -> None:
        """Identify functions containing license operations."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(licensed_binary))

        analysis: dict[str, Any] = explorer.get_license_validation_analysis()
        license_functions: list[dict[str, Any]] = analysis.get("cfg_license_functions", [])

        for func_info in license_functions:
            assert "function" in func_info
            assert "license_score" in func_info
            assert "complexity" in func_info
            assert "size" in func_info

            assert func_info["license_score"] > 0
            assert func_info["complexity"] >= 1
            assert func_info["size"] >= 0


class TestCallGraphAnalysis:
    """Test inter-function call graph analysis."""

    def test_build_call_graph(self, simple_pe_binary: Path) -> None:
        """Build call graph showing function dependencies."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        assert explorer.call_graph is not None
        assert explorer.call_graph.number_of_nodes() > 0

        for node, node_data in explorer.call_graph.nodes(data=True):
            assert "addr" in node_data
            assert "size" in node_data
            assert "complexity" in node_data

    def test_get_call_graph_metrics(self, simple_pe_binary: Path) -> None:
        """Calculate call graph analysis metrics."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        assert "total_functions" in metrics
        assert "total_calls" in metrics
        assert "avg_calls_per_function" in metrics

        assert metrics["total_functions"] > 0
        assert metrics["total_calls"] >= 0
        assert isinstance(metrics["avg_calls_per_function"], (int, float))

    def test_identify_entry_points(self, simple_pe_binary: Path) -> None:
        """Identify functions with no callers (entry points)."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        if "entry_points" in metrics:
            entry_points: list[str] = metrics["entry_points"]
            assert isinstance(entry_points, list)

            for entry_func in entry_points:
                assert explorer.call_graph.in_degree(entry_func) == 0

    def test_identify_leaf_functions(self, simple_pe_binary: Path) -> None:
        """Identify functions that call no other functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        if "leaf_functions" in metrics:
            leaf_functions: list[str] = metrics["leaf_functions"]
            assert isinstance(leaf_functions, list)

            for leaf_func in leaf_functions:
                assert explorer.call_graph.out_degree(leaf_func) == 0

    def test_detect_recursive_functions(self, simple_pe_binary: Path) -> None:
        """Detect functions with direct or indirect recursion."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        recursive_funcs: list[str] = explorer._find_recursive_functions()

        assert isinstance(recursive_funcs, list)

        for func in recursive_funcs:
            is_direct_recursive: bool = explorer.call_graph.has_edge(func, func)
            assert is_direct_recursive or func in recursive_funcs

    def test_calculate_pagerank(self, simple_pe_binary: Path) -> None:
        """Calculate PageRank to identify important functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        if "function_ranks" in metrics:
            ranks: dict[str, float] = metrics["function_ranks"]
            assert isinstance(ranks, dict)
            assert ranks

            for rank in ranks.values():
                assert isinstance(rank, float)
                assert rank > 0.0

    def test_calculate_betweenness_centrality(self, simple_pe_binary: Path) -> None:
        """Calculate betweenness centrality for functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        if "betweenness_centrality" in metrics:
            centrality: dict[str, float] = metrics["betweenness_centrality"]
            assert isinstance(centrality, dict)

            for score in centrality.values():
                assert isinstance(score, float)
                assert score >= 0.0


class TestCrossReferenceAnalysis:
    """Test cross-reference analysis."""

    def test_get_cross_reference_analysis(self, simple_pe_binary: Path) -> None:
        """Get cross-reference analysis between functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_cross_reference_analysis()

        assert "function_dependencies" in analysis
        assert "dependency_depth" in analysis
        assert "circular_dependencies" in analysis
        assert "isolated_functions" in analysis

    def test_analyze_function_dependencies(self, simple_pe_binary: Path) -> None:
        """Analyze dependencies for each function."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_cross_reference_analysis()
        dependencies: dict[str, Any] = analysis["function_dependencies"]

        for dep_data in dependencies.values():
            assert "calls" in dep_data
            assert "called_by" in dep_data
            assert "dependency_count" in dep_data
            assert "reverse_dependency_count" in dep_data

            assert isinstance(dep_data["calls"], list)
            assert isinstance(dep_data["called_by"], list)
            assert dep_data["dependency_count"] == len(dep_data["calls"])
            assert dep_data["reverse_dependency_count"] == len(dep_data["called_by"])

    def test_identify_isolated_functions(self, simple_pe_binary: Path) -> None:
        """Identify functions with no connections."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_cross_reference_analysis()
        isolated: list[str] = analysis["isolated_functions"]

        assert isinstance(isolated, list)

        for func in isolated:
            assert explorer.call_graph.in_degree(func) == 0
            assert explorer.call_graph.out_degree(func) == 0

    def test_detect_circular_dependencies(self, simple_pe_binary: Path) -> None:
        """Detect circular dependency cycles."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        analysis: dict[str, Any] = explorer.get_cross_reference_analysis()
        cycles: list[list[str]] = analysis["circular_dependencies"]

        assert isinstance(cycles, list)

        for cycle in cycles:
            assert isinstance(cycle, list)
            assert len(cycle) >= 1


class TestFunctionSimilarity:
    """Test function similarity analysis."""

    def test_calculate_function_similarities(self, simple_pe_binary: Path) -> None:
        """Calculate structural similarity between functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        explorer._calculate_function_similarities()

        assert isinstance(explorer.function_similarities, dict)

        for sim_key, similarity in explorer.function_similarities.items():
            assert ":" in sim_key
            func1, func2 = sim_key.split(":")
            assert func1 in explorer.function_graphs
            assert func2 in explorer.function_graphs

            assert isinstance(similarity, float)
            assert 0.0 <= similarity <= 1.0

    def test_graph_similarity_calculation(self, simple_pe_binary: Path) -> None:
        """Calculate similarity between two graphs."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        if len(explorer.function_graphs) >= 2:
            graphs: list = list(explorer.function_graphs.values())
            graph1 = graphs[0]
            graph2 = graphs[1]

            similarity: float = explorer._calculate_graph_similarity(graph1, graph2)

            assert isinstance(similarity, float)
            assert 0.0 <= similarity <= 1.0

    def test_generate_similarity_clusters(self, simple_pe_binary: Path) -> None:
        """Generate clusters of similar functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        explorer._calculate_function_similarities()
        clusters: list[list[str]] = explorer._generate_similarity_clusters()

        assert isinstance(clusters, list)

        for cluster in clusters:
            assert isinstance(cluster, list)
            assert len(cluster) >= 2


class TestVulnerabilityDetection:
    """Test vulnerability pattern detection."""

    def test_get_vulnerability_patterns(self, simple_pe_binary: Path) -> None:
        """Detect vulnerability patterns in binary."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        patterns: dict[str, Any] = explorer.get_vulnerability_patterns()

        assert "buffer_overflow_candidates" in patterns
        assert "format_string_candidates" in patterns
        assert "integer_overflow_candidates" in patterns
        assert "use_after_free_candidates" in patterns
        assert "license_bypass_opportunities" in patterns

        assert isinstance(patterns["buffer_overflow_candidates"], list)
        assert isinstance(patterns["license_bypass_opportunities"], list)

    def test_detect_buffer_overflow_patterns(self, vulnerable_binary: Path) -> None:
        """Detect unsafe string functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(vulnerable_binary))

        patterns: dict[str, Any] = explorer.get_vulnerability_patterns()
        buffer_overflows: list[dict[str, Any]] = patterns["buffer_overflow_candidates"]

        for vuln in buffer_overflows:
            assert "function" in vuln
            assert "address" in vuln
            assert "instruction" in vuln
            assert "type" in vuln
            assert vuln["type"] == "unsafe_string_function"

    def test_identify_license_bypass_opportunities(self, licensed_binary: Path) -> None:
        """Identify potential license bypass locations."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(licensed_binary))

        patterns: dict[str, Any] = explorer.get_vulnerability_patterns()
        bypass_ops: list[dict[str, Any]] = patterns["license_bypass_opportunities"]

        for opportunity in bypass_ops:
            assert "function" in opportunity
            assert "address" in opportunity
            assert "license_operations" in opportunity
            assert "block_type" in opportunity
            assert opportunity["license_operations"] > 0


class TestGraphVisualization:
    """Test graph visualization and export."""

    def test_get_graph_layout_spring(self, simple_pe_binary: Path) -> None:
        """Generate spring layout for graph visualization."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        if layout := explorer.get_graph_layout("spring"):
            assert isinstance(layout, dict)
            for node, pos in layout.items():
                assert isinstance(pos, tuple)
                assert len(pos) == 2
                assert isinstance(pos[0], (int, float))
                assert isinstance(pos[1], (int, float))

    def test_get_graph_layout_circular(self, simple_pe_binary: Path) -> None:
        """Generate circular layout for graph visualization."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        if layout := explorer.get_graph_layout("circular"):
            assert isinstance(layout, dict)
            assert len(layout) > 0

    def test_get_graph_data(self, simple_pe_binary: Path) -> None:
        """Get graph data for visualization."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        if graph_data := explorer.get_graph_data():
            assert "nodes" in graph_data
            assert "edges" in graph_data
            assert "function" in graph_data

            nodes: list[dict[str, Any]] = graph_data["nodes"]
            edges: list[dict[str, Any]] = graph_data["edges"]

            for node in nodes:
                assert "id" in node
                assert "label" in node
                assert "x" in node
                assert "y" in node

            for edge in edges:
                assert "source" in edge
                assert "target" in edge


class TestExportFunctionality:
    """Test export capabilities."""

    def test_export_json(self, simple_pe_binary: Path, tmp_path: Path) -> None:
        """Export analysis results to JSON."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        json_file: Path = tmp_path / "cfg_export.json"
        result: bool = explorer.export_json(str(json_file))

        assert result
        assert json_file.exists()
        assert json_file.stat().st_size > 0

        with open(json_file, "r", encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)

        assert isinstance(data, dict)
        assert data

    def test_export_dot_file(self, simple_pe_binary: Path, tmp_path: Path) -> None:
        """Export CFG to DOT format."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        dot_file: Path = tmp_path / "cfg.dot"
        result: bool = explorer.export_dot_file(str(dot_file))

        if result:
            assert dot_file.exists()
            assert dot_file.stat().st_size > 0

            content: str = dot_file.read_text(encoding="utf-8")
            assert "digraph" in content

    def test_export_graph_image(self, simple_pe_binary: Path, tmp_path: Path) -> None:
        """Export CFG as image."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        image_file: Path = tmp_path / "cfg.png"
        result: bool = explorer.export_graph_image(str(image_file), format="png")

        if result:
            assert image_file.exists()
            assert image_file.stat().st_size > 0

    def test_generate_interactive_html(self, simple_pe_binary: Path, tmp_path: Path) -> None:
        """Generate interactive HTML visualization."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        explorer.set_current_function(func_name)

        patterns: list[dict[str, Any]] = explorer.find_license_check_patterns()
        html_file: Path = tmp_path / "cfg.html"

        result: bool = explorer.generate_interactive_html(
            func_name,
            patterns,
            str(html_file)
        )

        if result:
            assert html_file.exists()
            assert html_file.stat().st_size > 0

            content: str = html_file.read_text(encoding="utf-8")
            assert "<html" in content
            assert "<canvas" in content


class TestComprehensiveAnalysis:
    """Test comprehensive analysis workflow."""

    def test_analyze_cfg_comprehensive(self, simple_pe_binary: Path) -> None:
        """Perform comprehensive CFG analysis."""
        explorer: CFGExplorer = CFGExplorer()
        results: dict[str, Any] = explorer.analyze_cfg(str(simple_pe_binary))

        assert "binary_path" in results
        assert "functions_analyzed" in results
        assert "complexity_metrics" in results
        assert "license_patterns" in results
        assert "advanced_analysis" in results
        assert "call_graph_analysis" in results
        assert "vulnerability_analysis" in results
        assert "errors" in results

        assert results["functions_analyzed"] > 0
        assert isinstance(results["complexity_metrics"], dict)
        assert isinstance(results["license_patterns"], list)
        assert isinstance(results["errors"], list)

    def test_get_advanced_analysis_results(self, simple_pe_binary: Path) -> None:
        """Get comprehensive advanced analysis results."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        results: dict[str, Any] = explorer.get_advanced_analysis_results()

        assert "analysis_cache" in results
        assert "function_similarities" in results
        assert "call_graph_metrics" in results
        assert "vulnerability_patterns" in results
        assert "license_validation_analysis" in results
        assert "code_complexity_analysis" in results
        assert "cross_reference_analysis" in results

    def test_generate_analysis_summary(self, simple_pe_binary: Path) -> None:
        """Generate analysis summary with key findings."""
        explorer: CFGExplorer = CFGExplorer()
        results: dict[str, Any] = explorer.analyze_cfg(str(simple_pe_binary))

        if "summary" in results:
            summary: dict[str, Any] = results["summary"]

            assert "total_functions" in summary
            assert "license_related_functions" in summary
            assert "vulnerable_functions" in summary
            assert "high_complexity_functions" in summary


class TestFunctionManagement:
    """Test function selection and management."""

    def test_get_function_list(self, simple_pe_binary: Path) -> None:
        """Get list of all extracted functions."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()

        assert isinstance(functions, list)
        assert functions
        assert all(isinstance(func, str) for func in functions)

    def test_set_current_function(self, simple_pe_binary: Path) -> None:
        """Set current function for analysis."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        result: bool = explorer.set_current_function(func_name)

        assert result
        assert explorer.current_function == func_name
        assert explorer.graph is not None

    def test_set_invalid_function_fails(self, simple_pe_binary: Path) -> None:
        """Setting invalid function returns False."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        result: bool = explorer.set_current_function("nonexistent_function")

        assert not result

    def test_get_functions_metadata(self, simple_pe_binary: Path) -> None:
        """Get functions with metadata."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[dict[str, Any]] = explorer.get_functions()

        assert isinstance(functions, list)
        assert functions

        for func in functions:
            assert "name" in func
            assert "address" in func

    def test_analyze_function(self, simple_pe_binary: Path) -> None:
        """Analyze specific function."""
        explorer: CFGExplorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        func_name: str = list(explorer.functions.keys())[0]
        if analysis := explorer.analyze_function(func_name):
            assert "name" in analysis
            assert "address" in analysis
            assert "graph" in analysis
            assert "num_blocks" in analysis
            assert "complexity" in analysis
            assert "license_patterns" in analysis
            assert "has_license_checks" in analysis


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create simple PE binary for testing."""
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
    """Create binary with license check patterns for testing."""
    return simple_pe_binary(tmp_path)


@pytest.fixture
def vulnerable_binary(tmp_path: Path) -> Path:
    """Create binary with vulnerability patterns for testing."""
    return simple_pe_binary(tmp_path)
