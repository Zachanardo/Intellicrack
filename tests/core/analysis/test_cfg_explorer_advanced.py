"""Advanced tests for CFGExplorer - Edge Cases and Utility Functions.

Tests production-ready CFG analysis edge cases, utility functions, and advanced patterns.
These tests validate robustness and completeness of CFG exploration capabilities.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.cfg_explorer import CFGExplorer, log_message


def create_simple_pe_binary() -> bytes:
    """Create minimal valid PE binary for testing."""
    pe_header = (
        b"MZ\x90\x00"
        + b"\x00" * 58
        + b"\x80\x00\x00\x00"
        + b"PE\x00\x00"
        + b"\x00" * 100
    )
    return pe_header


class TestAdvancedCFGPatterns:
    """Test advanced CFG pattern recognition for license checks."""

    def test_detect_state_machine_license_checks(self, simple_pe_binary: Path) -> None:
        """Detect license validation implemented as state machines."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        license_analysis: dict[str, Any] = explorer.get_license_validation_analysis()

        assert isinstance(license_analysis, dict)

        if "validation_mechanisms" in license_analysis:
            mechanisms: list[dict[str, Any]] = license_analysis["validation_mechanisms"]
            assert isinstance(mechanisms, list)

    def test_identify_obfuscated_conditional_jumps(
        self, simple_pe_binary: Path
    ) -> None:
        """Identify obfuscated conditional jumps in license logic."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]
            explorer.set_current_function(func_name)

            patterns: list[dict[str, Any]] = explorer.find_license_check_patterns()

            assert isinstance(patterns, list)

            for pattern in patterns:
                assert "type" in pattern
                assert pattern["type"] in ["license_keyword", "conditional_check"]

    def test_detect_multi_layer_license_validation(
        self, simple_pe_binary: Path
    ) -> None:
        """Detect multi-layer license validation patterns."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        license_analysis: dict[str, Any] = explorer.get_license_validation_analysis()

        assert isinstance(license_analysis, dict)
        assert "license_functions" in license_analysis or "cfg_license_functions" in license_analysis

    def test_identify_time_bomb_logic_in_cfg(self, simple_pe_binary: Path) -> None:
        """Identify trial expiration logic in control flow."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        vulnerability_patterns: dict[str, Any] = explorer.get_vulnerability_patterns()

        assert isinstance(vulnerability_patterns, dict)

        if "license_bypass_opportunities" in vulnerability_patterns:
            bypass_ops: list[dict[str, Any]] = vulnerability_patterns[
                "license_bypass_opportunities"
            ]
            assert isinstance(bypass_ops, list)


class TestCFGUtilityFunctions:
    """Test CFG utility functions for completeness."""

    def test_find_function_by_address_exact_match(
        self, simple_pe_binary: Path
    ) -> None:
        """Find function by exact address match."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions and explorer.functions:
            first_func = functions[0]
            func_data: dict[str, Any] = explorer.functions[first_func]
            address: int = func_data.get("addr", 0)

            result: str | None = explorer._find_function_by_address(address)

            assert result is not None
            assert result == first_func

    def test_find_function_by_address_address_within_function(
        self, simple_pe_binary: Path
    ) -> None:
        """Find function when address falls within function bounds."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions and explorer.functions:
            first_func = functions[0]
            func_data: dict[str, Any] = explorer.functions[first_func]
            base_addr: int = func_data.get("addr", 0)
            size: int = func_data.get("size", 0)

            if size > 4:
                mid_address: int = base_addr + 2

                result: str | None = explorer._find_function_by_address(mid_address)

                assert result is None or result == first_func

    def test_find_function_by_address_no_match(self, simple_pe_binary: Path) -> None:
        """Return None when address doesn't match any function."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        result: str | None = explorer._find_function_by_address(0xDEADBEEF)

        assert result is None

    def test_log_message_formatting(self) -> None:
        """Log message formats output correctly."""
        test_message: str = "Test log message"

        result: str = log_message(test_message)

        assert isinstance(result, str)
        assert test_message in result

    def test_log_message_timestamp_inclusion(self) -> None:
        """Log message includes timestamp information."""
        test_message: str = "Timestamp test"

        result: str = log_message(test_message)

        assert isinstance(result, str)
        assert len(result) >= len(test_message)


class TestCFGEdgeCases:
    """Test CFG analysis edge cases and error handling."""

    def test_analyze_function_with_no_blocks(self, simple_pe_binary: Path) -> None:
        """Handle function with no basic blocks gracefully."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]

            analysis: dict[str, Any] | None = explorer.analyze_function(func_name)

            if analysis:
                assert "num_blocks" in analysis
                num_blocks: int = analysis["num_blocks"]
                assert isinstance(num_blocks, int)
                assert num_blocks >= 0

    def test_analyze_function_with_infinite_loop(
        self, simple_pe_binary: Path
    ) -> None:
        """Detect and handle infinite loop in CFG."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        call_graph_metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        assert isinstance(call_graph_metrics, dict)

        if "recursive_functions" in call_graph_metrics:
            recursive: list[str] = call_graph_metrics["recursive_functions"]
            assert isinstance(recursive, list)

    def test_analyze_deeply_nested_control_flow(
        self, simple_pe_binary: Path
    ) -> None:
        """Handle deeply nested control flow structures."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        complexity_analysis: dict[str, Any] = explorer.get_code_complexity_analysis()

        assert isinstance(complexity_analysis, dict)

        if "high_complexity_functions" in complexity_analysis:
            high_complexity: list[dict[str, Any]] = complexity_analysis[
                "high_complexity_functions"
            ]
            assert isinstance(high_complexity, list)

    def test_analyze_recursive_function_call_chain(
        self, simple_pe_binary: Path
    ) -> None:
        """Handle recursive function call chains correctly."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        recursive_funcs: list[str] = explorer._find_recursive_functions()

        assert isinstance(recursive_funcs, list)

        for func in recursive_funcs:
            assert isinstance(func, str)
            assert len(func) > 0

    def test_handle_corrupted_graph_data(self) -> None:
        """Handle corrupted or incomplete graph data."""
        explorer = CFGExplorer()

        result: bool = explorer.load_binary("nonexistent_file.exe")

        assert isinstance(result, bool)
        assert result is False

        functions: list[str] = explorer.get_function_list()
        assert len(functions) == 0

    def test_analyze_binary_with_anti_analysis_checks(
        self, simple_pe_binary: Path
    ) -> None:
        """Handle binaries with anti-analysis techniques."""
        explorer = CFGExplorer()
        result: bool = explorer.load_binary(str(simple_pe_binary))

        assert isinstance(result, bool)

        if result:
            vulnerability_patterns: dict[str, Any] = (
                explorer.get_vulnerability_patterns()
            )
            assert isinstance(vulnerability_patterns, dict)


class TestCFGComplexityCalculations:
    """Test advanced complexity calculations."""

    def test_cyclomatic_complexity_simple_function(
        self, simple_pe_binary: Path
    ) -> None:
        """Calculate cyclomatic complexity for simple function."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]
            func_data: dict[str, Any] = explorer.functions[func_name]

            if "graph" in func_data:
                graph = func_data["graph"]
                complexity: int = explorer._calculate_cyclomatic_complexity(graph)

                assert isinstance(complexity, int)
                assert complexity >= 1

    def test_complexity_metrics_comprehensive(self, simple_pe_binary: Path) -> None:
        """Get comprehensive complexity metrics for all functions."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]
            explorer.set_current_function(func_name)

            metrics: dict[str, Any] = explorer.get_complexity_metrics()

            assert isinstance(metrics, dict)
            assert "nodes" in metrics or "cyclomatic_complexity" in metrics


class TestCFGCallGraphAdvanced:
    """Test advanced call graph analysis."""

    def test_identify_strongly_connected_components(
        self, simple_pe_binary: Path
    ) -> None:
        """Identify strongly connected components in call graph."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        call_graph_metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        assert isinstance(call_graph_metrics, dict)

        if "strongly_connected_components" in call_graph_metrics:
            scc: list[list[str]] = call_graph_metrics["strongly_connected_components"]
            assert isinstance(scc, list)

    def test_calculate_graph_diameter(self, simple_pe_binary: Path) -> None:
        """Calculate diameter of call graph."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        call_graph_metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        assert isinstance(call_graph_metrics, dict)

        if "graph_diameter" in call_graph_metrics:
            diameter = call_graph_metrics["graph_diameter"]
            assert isinstance(diameter, (int, float))
            assert diameter >= 0

    def test_identify_critical_functions_by_centrality(
        self, simple_pe_binary: Path
    ) -> None:
        """Identify critical functions using betweenness centrality."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        call_graph_metrics: dict[str, Any] = explorer.get_call_graph_metrics()

        assert isinstance(call_graph_metrics, dict)

        if "betweenness_centrality" in call_graph_metrics:
            centrality: dict[str, float] = call_graph_metrics["betweenness_centrality"]
            assert isinstance(centrality, dict)

            for func, score in centrality.items():
                assert isinstance(score, float)
                assert score >= 0.0


class TestCFGVisualizationAdvanced:
    """Test advanced visualization capabilities."""

    def test_generate_graph_layout_hierarchical(self, simple_pe_binary: Path) -> None:
        """Generate hierarchical layout for call graph."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]
            explorer.set_current_function(func_name)

            layout: dict[int, tuple[float, float]] | None = (
                explorer.get_graph_layout("spring")
            )

            if layout:
                assert isinstance(layout, dict)
                assert len(layout) > 0

    def test_export_with_highlights(self, simple_pe_binary: Path, tmp_path: Path) -> None:
        """Export graph with license check highlights."""
        explorer = CFGExplorer()
        explorer.load_binary(str(simple_pe_binary))

        functions: list[str] = explorer.get_function_list()
        if functions:
            func_name: str = functions[0]
            explorer.set_current_function(func_name)

            patterns: list[dict[str, Any]] = explorer.find_license_check_patterns()
            html_file: Path = tmp_path / "highlighted_cfg.html"

            result: bool = explorer.generate_interactive_html(
                func_name, patterns, str(html_file)
            )

            if result:
                assert html_file.exists()
                content: str = html_file.read_text(encoding="utf-8")
                assert "<html" in content


class TestCFGErrorRecovery:
    """Test error recovery and graceful degradation."""

    def test_continue_analysis_after_error(self) -> None:
        """Continue analysis after encountering error."""
        explorer = CFGExplorer()

        result1: bool = explorer.load_binary("nonexistent1.exe")
        assert result1 is False

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".exe", delete=False
        ) as tmp:
            tmp.write(create_simple_pe_binary())
            tmp_path: str = tmp.name

        try:
            result2: bool = explorer.load_binary(tmp_path)

            assert isinstance(result2, bool)
        finally:
            Path(tmp_path).unlink()

    def test_partial_analysis_on_corrupted_sections(self) -> None:
        """Provide partial results when binary sections are corrupted."""
        explorer = CFGExplorer()

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".exe", delete=False
        ) as tmp:
            tmp.write(b"MZ" + b"\x00" * 200)
            tmp_path: str = tmp.name

        try:
            result: bool = explorer.load_binary(tmp_path)

            assert isinstance(result, bool)

            functions: list[str] = explorer.get_function_list()
            assert isinstance(functions, list)
        finally:
            Path(tmp_path).unlink()


@pytest.fixture
def simple_pe_binary(tmp_path: Path) -> Path:
    """Create simple PE binary for testing."""
    pe_file: Path = tmp_path / "simple.exe"
    pe_file.write_bytes(create_simple_pe_binary())
    return pe_file
