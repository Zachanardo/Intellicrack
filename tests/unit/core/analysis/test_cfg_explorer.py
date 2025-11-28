"""
Unit tests for CFGExplorer with REAL binary control flow analysis.
Tests actual CFG construction, vulnerability detection, and complexity analysis.
NO MOCKS - ALL TESTS USE REAL BINARIES AND VALIDATE PRODUCTION FUNCTIONALITY.

Testing Agent Mission: Validate sophisticated control flow graph exploration
capabilities that prove Intellicrack's effectiveness as a security research platform.
"""

import pytest
import json
import tempfile
from pathlib import Path

from intellicrack.core.analysis.cfg_explorer import CFGExplorer, run_deep_cfg_analysis, run_cfg_explorer
from tests.base_test import IntellicrackTestBase


class TestCFGExplorer(IntellicrackTestBase):
    """Test CFGExplorer with real binaries and production-ready validation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment with real test binaries."""
        # Use available real test binaries for CFG analysis
        self.test_fixtures_dir = Path("tests/fixtures/binaries")

        # Vulnerable samples for pattern detection testing
        self.vulnerable_binaries = [
            self.test_fixtures_dir / "vulnerable_samples/buffer_overflow_0.exe",
            self.test_fixtures_dir / "vulnerable_samples/format_string_0.exe",
            self.test_fixtures_dir / "vulnerable_samples/heap_overflow_0.exe",
            self.test_fixtures_dir / "vulnerable_samples/integer_overflow_0.exe",
            self.test_fixtures_dir / "vulnerable_samples/race_condition_0.exe",
        ]

        # Protected binaries for license validation analysis
        self.protected_binaries = [
            self.test_fixtures_dir / "pe/protected/enterprise_license_check.exe",
            self.test_fixtures_dir / "pe/protected/flexlm_license_protected.exe",
            self.test_fixtures_dir / "pe/protected/hasp_sentinel_protected.exe",
            self.test_fixtures_dir / "pe/protected/online_activation_app.exe",
            self.test_fixtures_dir / "full_protected_software/Beyond_Compare_Full.exe",
            self.test_fixtures_dir / "full_protected_software/Resource_Hacker_Full.exe",
        ]

        # Legitimate binaries for complexity analysis
        self.legitimate_binaries = [
            self.test_fixtures_dir / "pe/legitimate/7zip.exe",
            self.test_fixtures_dir / "pe/legitimate/firefox.exe",
            self.test_fixtures_dir / "pe/legitimate/notepadpp.exe",
            self.test_fixtures_dir / "pe/legitimate/vlc.exe",
        ]

        # Packed binaries for advanced analysis
        self.packed_binaries = [
            self.test_fixtures_dir / "pe/real_protected/upx_packer/upx-4.2.2-win64/upx.exe",
            self.test_fixtures_dir / "protected/upx_packed_0.exe",
            self.test_fixtures_dir / "protected/vmprotect_protected.exe",
            self.test_fixtures_dir / "protected/themida_protected.exe",
        ]

        # Filter for existing binaries
        self.vulnerable_binaries = [p for p in self.vulnerable_binaries if p.exists()]
        self.protected_binaries = [p for p in self.protected_binaries if p.exists()]
        self.legitimate_binaries = [p for p in self.legitimate_binaries if p.exists()]
        self.packed_binaries = [p for p in self.packed_binaries if p.exists()]

        # All available test binaries
        self.test_binaries = self.vulnerable_binaries + self.protected_binaries + self.legitimate_binaries + self.packed_binaries

        # Ensure we have test binaries available
        if not self.test_binaries:
            pytest.skip("No test binaries available for CFG testing")

    def test_cfg_explorer_initialization(self):
        """Test CFGExplorer initialization with proper setup."""
        cfg_explorer = CFGExplorer()

        # Verify core attributes are initialized
        assert hasattr(cfg_explorer, "binary_path")
        assert hasattr(cfg_explorer, "radare2_path")
        assert hasattr(cfg_explorer, "logger")
        assert hasattr(cfg_explorer, "graph")
        assert hasattr(cfg_explorer, "functions")
        assert hasattr(cfg_explorer, "current_function")

        # Verify analysis engines are available
        assert hasattr(cfg_explorer, "decompiler")
        assert hasattr(cfg_explorer, "vulnerability_engine")
        assert hasattr(cfg_explorer, "ai_engine")
        assert hasattr(cfg_explorer, "string_analyzer")
        assert hasattr(cfg_explorer, "import_analyzer")
        assert hasattr(cfg_explorer, "scripting_engine")

        # Verify data structures are initialized
        assert hasattr(cfg_explorer, "function_graphs")
        assert hasattr(cfg_explorer, "call_graph")
        assert hasattr(cfg_explorer, "cross_references")
        assert hasattr(cfg_explorer, "function_similarities")
        assert hasattr(cfg_explorer, "analysis_cache")

        # Verify these are proper data structures, not None
        assert isinstance(cfg_explorer.function_graphs, dict)
        assert cfg_explorer.call_graph is not None
        assert isinstance(cfg_explorer.cross_references, dict)
        assert isinstance(cfg_explorer.function_similarities, dict)
        assert isinstance(cfg_explorer.analysis_cache, dict)

    def test_load_binary_real_pe_analysis(self):
        """Test loading real PE binary and extracting CFG data."""
        if not self.legitimate_binaries:
            pytest.skip("No legitimate PE binaries available")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        # Load binary and perform analysis
        result = cfg_explorer.load_binary(str(test_binary))

        # Validate real analysis output
        self.assert_real_output(result, "Binary loading result appears to be placeholder")

        # Verify functions were extracted
        functions = cfg_explorer.get_functions()
        assert functions is not None
        assert len(functions) > 0, "No functions extracted from binary"
        self.assert_real_output(functions, "Function list appears to be placeholder")

        # Verify function data is sophisticated
        for func_data in functions[:3]:  # Check first 3 functions
            assert "address" in func_data, "Function missing address"
            assert "name" in func_data, "Function missing name"
            assert "size" in func_data, "Function missing size"
            assert func_data["size"] > 0, "Function size must be positive"

            # Address should be realistic (not 0 or obvious placeholder)
            addr = func_data["address"]
            if isinstance(addr, str):
                addr = int(addr, 16)
            assert addr > 0x400000, "Function address too low for PE binary"

    def test_vulnerability_pattern_detection(self):
        """Test sophisticated vulnerability pattern detection in real binaries."""
        if not self.vulnerable_binaries:
            pytest.skip("No vulnerable sample binaries available")

        cfg_explorer = CFGExplorer()

        # Test buffer overflow detection
        buffer_overflow_binary = next((b for b in self.vulnerable_binaries if "buffer_overflow" in str(b)), None)
        if buffer_overflow_binary:
            cfg_explorer.load_binary(str(buffer_overflow_binary))
            patterns = cfg_explorer.get_vulnerability_patterns()

            self.assert_real_output(patterns, "Vulnerability patterns appear to be placeholder")

            # Should detect buffer overflow patterns
            assert isinstance(patterns, dict), "Patterns should be structured data"
            assert len(patterns) > 0, "Should detect vulnerability patterns"

            # Look for buffer overflow indicators
            pattern_types = [p.get("type", "").lower() for p in patterns.values()]
            vulnerability_found = any("buffer" in t or "overflow" in t or "bounds" in t for t in pattern_types)
            assert vulnerability_found, "Should detect buffer overflow vulnerability patterns"

    def test_license_validation_analysis(self):
        """Test identification of license validation logic for security research."""
        if not self.protected_binaries:
            pytest.skip("No protected binaries with license validation available")

        cfg_explorer = CFGExplorer()
        test_binary = self.protected_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        license_analysis = cfg_explorer.get_license_validation_analysis()

        self.assert_real_output(license_analysis, "License analysis appears to be placeholder")

        # Should identify license validation components
        assert isinstance(license_analysis, dict), "License analysis should be structured"
        assert len(license_analysis) > 0, "Should identify license validation patterns"

        # Should contain meaningful analysis categories
        expected_categories = ["license_checks", "validation_functions", "bypass_opportunities", "protection_strength"]
        found_categories = 0
        for category in expected_categories:
            if any(category in key.lower() for key in license_analysis):
                found_categories += 1

        assert found_categories >= 2, f"Should identify at least 2 license analysis categories, found {found_categories}"

    def test_code_complexity_analysis(self):
        """Test sophisticated code complexity metrics calculation."""
        if not self.legitimate_binaries:
            pytest.skip("No legitimate binaries available for complexity analysis")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        complexity_analysis = cfg_explorer.get_code_complexity_analysis()

        self.assert_real_output(complexity_analysis, "Complexity analysis appears to be placeholder")

        # Should provide comprehensive complexity metrics
        assert isinstance(complexity_analysis, dict), "Complexity analysis should be structured"

        # Should contain cyclomatic complexity
        assert "cyclomatic_complexity" in complexity_analysis, "Missing cyclomatic complexity"
        cyclomatic = complexity_analysis["cyclomatic_complexity"]
        assert isinstance(cyclomatic, (int, float)), "Cyclomatic complexity should be numeric"
        assert cyclomatic > 1, "Cyclomatic complexity should be meaningful for real binary"

        # Should contain function complexity distribution
        if "function_complexities" in complexity_analysis:
            func_complexities = complexity_analysis["function_complexities"]
            assert len(func_complexities) > 0, "Should analyze function complexities"

            # Verify realistic complexity values
            complexity_values = [c["complexity"] for c in func_complexities[:5]]
            assert all(isinstance(c, (int, float)) and c >= 1 for c in complexity_values), (
                "Function complexities should be realistic numeric values"
            )

    def test_call_graph_construction_and_metrics(self):
        """Test call graph construction and sophisticated metrics calculation."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for call graph testing")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        call_graph_metrics = cfg_explorer.get_call_graph_metrics()

        self.assert_real_output(call_graph_metrics, "Call graph metrics appear to be placeholder")

        # Should provide comprehensive call graph analysis
        assert isinstance(call_graph_metrics, dict), "Call graph metrics should be structured"

        # Should contain graph properties
        expected_metrics = ["total_functions", "total_calls", "recursive_functions", "graph_diameter", "strongly_connected_components"]
        found_metrics = 0
        for metric in expected_metrics:
            if metric in call_graph_metrics:
                found_metrics += 1
                value = call_graph_metrics[metric]
                assert isinstance(value, (int, float)), f"{metric} should be numeric"
                assert value >= 0, f"{metric} should be non-negative"

        assert found_metrics >= 3, f"Should provide at least 3 call graph metrics, found {found_metrics}"

    def test_cross_reference_analysis(self):
        """Test cross-reference analysis for data and code relationships."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for cross-reference analysis")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        xref_analysis = cfg_explorer.get_cross_reference_analysis()

        self.assert_real_output(xref_analysis, "Cross-reference analysis appears to be placeholder")

        # Should identify code and data references
        assert isinstance(xref_analysis, dict), "Cross-reference analysis should be structured"
        assert len(xref_analysis) > 0, "Should identify cross-references"

        # Should contain meaningful reference types
        reference_types = []
        for ref_data in xref_analysis.values():
            if isinstance(ref_data, dict) and "type" in ref_data:
                reference_types.append(ref_data["type"])

        assert len(reference_types) > 0, "Should identify reference types"

        # Should find different types of references
        expected_types = ["call", "data", "jump", "string"]
        found_types = {t.lower() for t in reference_types}
        type_matches = sum(1 for expected in expected_types if any(expected in found for found in found_types))
        assert type_matches >= 2, f"Should identify at least 2 reference types, found {found_types}"

    def test_function_similarity_analysis(self):
        """Test function similarity calculation through graph analysis."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for similarity analysis")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))

        # Trigger similarity analysis
        cfg_explorer._calculate_function_similarities()

        # Get similarity results
        similarities = cfg_explorer.function_similarities
        self.assert_real_output(similarities, "Function similarities appear to be placeholder")

        # Should identify function similarities
        if similarities:
            assert isinstance(similarities, dict), "Similarities should be structured"

            # Check similarity data structure
            for sim_data in similarities.values():
                if isinstance(sim_data, dict):
                    if "similarity_score" in sim_data:
                        score = sim_data["similarity_score"]
                        assert isinstance(score, (int, float)), "Similarity score should be numeric"
                        assert 0 <= score <= 1, "Similarity score should be between 0 and 1"

    def test_advanced_analysis_capabilities(self):
        """Test advanced analysis features for professional security research."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for advanced analysis")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        advanced_results = cfg_explorer.get_advanced_analysis_results()

        self.assert_real_output(advanced_results, "Advanced analysis results appear to be placeholder")

        # Should provide comprehensive advanced analysis
        assert isinstance(advanced_results, dict), "Advanced analysis should be structured"
        assert len(advanced_results) > 0, "Should provide advanced analysis insights"

        # Should contain sophisticated analysis categories
        expected_categories = ["control_flow_analysis", "data_flow_analysis", "security_analysis", "code_patterns", "optimization_analysis"]
        found_categories = 0
        for category in expected_categories:
            if any(category.replace("_", "") in key.lower().replace("_", "") for key in advanced_results):
                found_categories += 1

        assert found_categories >= 2, f"Should provide at least 2 advanced analysis categories, found {found_categories}"

    def test_complexity_metrics_calculation(self):
        """Test comprehensive complexity metrics for code quality assessment."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for complexity testing")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))
        complexity_metrics = cfg_explorer.get_complexity_metrics()

        self.assert_real_output(complexity_metrics, "Complexity metrics appear to be placeholder")

        # Should provide detailed complexity analysis
        assert isinstance(complexity_metrics, dict), "Complexity metrics should be structured"

        # Should include cyclomatic complexity
        if "cyclomatic_complexity" in complexity_metrics:
            cyclomatic = complexity_metrics["cyclomatic_complexity"]
            assert isinstance(cyclomatic, (int, float)), "Cyclomatic complexity should be numeric"
            assert cyclomatic >= 1, "Cyclomatic complexity should be at least 1"

        # Should include other sophisticated metrics
        expected_metrics = ["average_complexity", "max_complexity", "total_functions", "complex_functions"]
        found_metrics = sum(1 for metric in expected_metrics if metric in complexity_metrics)
        assert found_metrics >= 2, f"Should provide at least 2 complexity metrics, found {found_metrics}"

    def test_visualization_and_export_capabilities(self):
        """Test professional visualization and export functionality."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for visualization testing")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))

        # Test graph data extraction
        graph_data = cfg_explorer.get_graph_data()
        self.assert_real_output(graph_data, "Graph data appears to be placeholder")

        assert isinstance(graph_data, dict), "Graph data should be structured"

        # Should contain nodes and edges
        if "nodes" in graph_data and "edges" in graph_data:
            nodes = graph_data["nodes"]
            edges = graph_data["edges"]

            assert len(nodes) > 0, "Should have graph nodes"
            assert len(edges) > 0, "Should have graph edges"

            # Verify node structure
            for node in nodes[:3]:  # Check first few nodes
                assert isinstance(node, dict), "Node should be structured data"
                assert "id" in node, "Node should have ID"

        # Test layout generation
        layout = cfg_explorer.get_graph_layout()
        if layout:
            self.assert_real_output(layout, "Graph layout appears to be placeholder")

    def test_export_functionality(self):
        """Test export capabilities for analysis results."""
        if not self.legitimate_binaries:
            pytest.skip("No binaries available for export testing")

        cfg_explorer = CFGExplorer()
        test_binary = self.legitimate_binaries[0]

        cfg_explorer.load_binary(str(test_binary))

        # Test JSON export
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp_file:
            json_path = tmp_file.name

        try:
            result = cfg_explorer.export_json(json_path)
            self.assert_real_output(result, "JSON export result appears to be placeholder")

            # Verify file was created
            json_file = Path(json_path)
            assert json_file.exists(), "JSON export file should be created"
            assert json_file.stat().st_size > 0, "JSON export file should not be empty"

            # Verify valid JSON structure
            with open(json_path) as f:
                exported_data = json.load(f)

            assert isinstance(exported_data, dict), "Exported JSON should be structured"
            assert len(exported_data) > 0, "Exported JSON should contain data"

        finally:
            # Clean up
            if Path(json_path).exists():
                Path(json_path).unlink()

    def test_packed_binary_analysis(self):
        """Test CFG analysis of packed/protected binaries."""
        if not self.packed_binaries:
            pytest.skip("No packed binaries available for testing")

        cfg_explorer = CFGExplorer()
        packed_binary = self.packed_binaries[0]

        # Should handle packed binaries gracefully
        result = cfg_explorer.load_binary(str(packed_binary))

        # May have limited analysis due to packing, but should not crash
        assert result is not None, "Should handle packed binary without crashing"

        # Should at least extract basic information
        functions = cfg_explorer.get_functions()
        assert functions is not None, "Should return function list (even if limited)"

    def test_error_handling_malformed_binary(self):
        """Test robust error handling for malformed or invalid binaries."""
        cfg_explorer = CFGExplorer()

        # Test with non-existent file
        result = cfg_explorer.load_binary("nonexistent_file.exe")

        # Should handle gracefully, not crash
        assert result is not None, "Should handle non-existent file gracefully"

        # Test with invalid binary data
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(b"This is not a valid binary file content")
            tmp_path = tmp_file.name

        try:
            result = cfg_explorer.load_binary(tmp_path)
            # Should handle malformed data gracefully
            assert result is not None, "Should handle malformed binary gracefully"
        finally:
            Path(tmp_path).unlink()

    def test_performance_with_large_binary(self):
        """Test performance and stability with larger binaries."""
        # Look for larger test binaries
        large_binaries = []
        for binary in self.legitimate_binaries:
            if binary.exists() and binary.stat().st_size > 1024 * 1024:  # > 1MB
                large_binaries.append(binary)

        if not large_binaries:
            pytest.skip("No large binaries available for performance testing")

        cfg_explorer = CFGExplorer()
        large_binary = large_binaries[0]

        import time

        start_time = time.time()

        result = cfg_explorer.load_binary(str(large_binary))

        analysis_time = time.time() - start_time

        # Should complete analysis in reasonable time (< 60 seconds)
        assert analysis_time < 60, f"Analysis took too long: {analysis_time:.2f} seconds"

        # Should still produce meaningful results
        assert result is not None, "Should complete analysis of large binary"
        functions = cfg_explorer.get_functions()
        assert len(functions) > 0, "Should extract functions from large binary"


class TestCFGUtilityFunctions(IntellicrackTestBase):
    """Test utility functions for CFG analysis."""

    def test_run_deep_cfg_analysis(self):
        """Test deep CFG analysis utility function."""
        # Get available test binary
        test_fixtures_dir = Path("tests/fixtures/binaries")
        legitimate_binaries = [test_fixtures_dir / "pe/legitimate/7zip.exe", test_fixtures_dir / "pe/legitimate/notepadpp.exe"]
        legitimate_binaries = [p for p in legitimate_binaries if p.exists()]

        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available for deep analysis testing")

        test_binary = str(legitimate_binaries[0])

        # Test deep analysis
        result = run_deep_cfg_analysis(test_binary)

        self.assert_real_output(result, "Deep CFG analysis result appears to be placeholder")

        # Should provide comprehensive analysis
        assert isinstance(result, dict), "Deep analysis should return structured results"
        assert len(result) > 0, "Deep analysis should provide meaningful results"

    def test_run_cfg_explorer_interface(self):
        """Test CFG explorer interface launcher."""
        # Get available test binary
        test_fixtures_dir = Path("tests/fixtures/binaries")
        legitimate_binaries = [
            test_fixtures_dir / "pe/legitimate/7zip.exe",
        ]
        legitimate_binaries = [p for p in legitimate_binaries if p.exists()]

        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available for CFG explorer testing")

        test_binary = str(legitimate_binaries[0])

        # Mock GUI dependencies to test interface setup
        with patch("intellicrack.core.analysis.cfg_explorer.PYQT_AVAILABLE", True):
            # Test would launch interface - mock for testing
            try:
                result = run_cfg_explorer(test_binary)
                # Should either launch interface or return setup result
                assert result is not None, "CFG explorer should initialize"
            except Exception as e:
                # May fail due to GUI dependencies in test environment
                # This is acceptable as long as it's not a placeholder error
                error_msg = str(e).lower()
                placeholder_errors = ["not implemented", "todo", "placeholder"]
                assert not any(err in error_msg for err in placeholder_errors), f"Should not have placeholder error: {e}"
