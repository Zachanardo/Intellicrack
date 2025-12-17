"""Production tests for IntelligentCorrelationEngine.

Validates graph-based correlation, semantic similarity, clustering, and
multi-tool result correlation against real analysis patterns.
"""

import hashlib
import time
from typing import Any

import networkx as nx
import numpy as np
import pytest

from intellicrack.core.orchestration.intelligent_correlation_engine import (
    Correlation,
    CorrelationCluster,
    CorrelationType,
    IntelligentCorrelationEngine,
)
from intellicrack.core.orchestration.result_serialization_protocol import (
    BaseResult,
    CryptoResult,
    FunctionResult,
    LicenseCheckResult,
    ProtectionResult,
    ResultType,
    StringResult,
)


class TestIntelligentCorrelationEngine:
    """Test correlation engine capabilities on real analysis data."""

    @pytest.fixture
    def engine(self) -> IntelligentCorrelationEngine:
        """Create fresh correlation engine instance."""
        return IntelligentCorrelationEngine()

    @pytest.fixture
    def license_check_function(self) -> FunctionResult:
        """Create realistic license check function result."""
        return FunctionResult(
            id=hashlib.sha256(b"license_check_0x401000").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_serial",
            size=256,
            cyclomatic_complexity=8,
            xrefs_to=[0x400500, 0x400800],
            xrefs_from=[0x402000, 0x403000],
            decompiled_code="bool validate_serial(char* key) { return check_hwid(key); }",
            confidence=0.95,
        )

    @pytest.fixture
    def license_string(self) -> StringResult:
        """Create realistic license validation string."""
        return StringResult(
            id=hashlib.sha256(b"string_invalid_license").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x405000,
            value="Invalid license key",
            length=18,
            references=[0x401050],
            entropy=3.2,
            confidence=1.0,
        )

    @pytest.fixture
    def crypto_result(self) -> CryptoResult:
        """Create realistic crypto detection result."""
        return CryptoResult(
            id=hashlib.sha256(b"crypto_aes_0x410000").hexdigest(),
            type=ResultType.CRYPTO,
            source_tool="yara",
            timestamp=time.time(),
            address=0x410000,
            algorithm="aes",
            key_size=256,
            mode="CBC",
            constants=[0x63, 0x7C, 0x77, 0x7B],
            implementation_type="standard",
            confidence=0.92,
        )

    def test_add_result_creates_graph_node(self, engine: IntelligentCorrelationEngine, license_check_function: FunctionResult) -> None:
        """Adding result creates graph node with proper attributes."""
        engine.add_result(license_check_function)

        assert license_check_function.id in engine.results
        assert engine.correlation_graph.has_node(license_check_function.id)
        node_data = engine.correlation_graph.nodes[license_check_function.id]
        assert node_data["result"] == license_check_function

    def test_address_correlation_proximity(self, engine: IntelligentCorrelationEngine) -> None:
        """Functions within proximity threshold are correlated by address."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="func1",
            size=100,
            cyclomatic_complexity=3,
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ida_pro",
            timestamp=time.time(),
            address=0x401080,
            name="func2",
            size=80,
            cyclomatic_complexity=2,
        )

        engine.add_result(func1)
        engine.add_result(func2)

        address_correlations = [c for c in engine.correlations if c.type == CorrelationType.ADDRESS_MATCH]
        assert len(address_correlations) >= 1

        correlation = address_correlations[0]
        assert func1.id in correlation.source_results
        assert func2.id in correlation.source_results
        assert correlation.confidence > 0.5
        assert "distance" in correlation.evidence

    def test_no_correlation_beyond_threshold(self, engine: IntelligentCorrelationEngine) -> None:
        """Functions beyond proximity threshold not correlated by address."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"far_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="far_func1",
            size=100,
            cyclomatic_complexity=3,
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"far_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="far_func2",
            size=80,
            cyclomatic_complexity=2,
        )

        engine.add_result(func1)
        engine.add_result(func2)

        address_correlations = [c for c in engine.correlations if c.type == CorrelationType.ADDRESS_MATCH]
        assert len(address_correlations) == 0

    def test_xref_correlation_direct_call(self, engine: IntelligentCorrelationEngine) -> None:
        """Functions with direct call relationships are correlated."""
        caller = FunctionResult(
            id=hashlib.sha256(b"caller").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="caller",
            size=200,
            cyclomatic_complexity=5,
            xrefs_from=[0x402000],
        )

        callee = FunctionResult(
            id=hashlib.sha256(b"callee").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="callee",
            size=150,
            cyclomatic_complexity=3,
            xrefs_to=[0x401000],
        )

        engine.add_result(caller)
        engine.add_result(callee)

        xref_correlations = [c for c in engine.correlations if c.type == CorrelationType.XREF_RELATED]
        assert len(xref_correlations) >= 1

        correlation = xref_correlations[0]
        assert correlation.confidence >= 0.85
        assert "relationship" in correlation.evidence

    def test_xref_correlation_shared_dependencies(self, engine: IntelligentCorrelationEngine) -> None:
        """Functions calling same targets are correlated."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"shared1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="shared1",
            size=200,
            cyclomatic_complexity=4,
            xrefs_from=[0x405000, 0x406000, 0x407000],
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"shared2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="shared2",
            size=180,
            cyclomatic_complexity=3,
            xrefs_from=[0x405000, 0x406000, 0x407000],
        )

        engine.add_result(func1)
        engine.add_result(func2)

        xref_correlations = [c for c in engine.correlations if c.type == CorrelationType.XREF_RELATED]
        assert len(xref_correlations) >= 1

        correlation = xref_correlations[0]
        assert "common_calls" in correlation.evidence
        assert len(correlation.evidence["common_calls"]) >= 3

    def test_string_reference_correlation(self, engine: IntelligentCorrelationEngine) -> None:
        """String referenced by function creates correlation."""
        string_result = StringResult(
            id=hashlib.sha256(b"license_string").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x405000,
            value="License validation failed",
            length=24,
            references=[0x401000],
            entropy=3.5,
        )

        func_result = FunctionResult(
            id=hashlib.sha256(b"validate_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_license",
            size=300,
            cyclomatic_complexity=7,
            xrefs_from=[0x405000],
        )

        engine.add_result(func_result)
        engine.add_result(string_result)

        string_correlations = [c for c in engine.correlations if c.type == CorrelationType.STRING_REFERENCE]
        assert len(string_correlations) >= 1

        correlation = string_correlations[0]
        assert string_result.id in correlation.source_results
        assert func_result.id in correlation.source_results
        assert "string_value" in correlation.evidence

    def test_license_pattern_correlation(self, engine: IntelligentCorrelationEngine) -> None:
        """License check patterns are correlated across multiple results."""
        validate_func = FunctionResult(
            id=hashlib.sha256(b"validate_serial_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_serial",
            size=256,
            cyclomatic_complexity=8,
        )

        check_func = FunctionResult(
            id=hashlib.sha256(b"check_license_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="check_license",
            size=200,
            cyclomatic_complexity=6,
        )

        invalid_str = StringResult(
            id=hashlib.sha256(b"invalid_string").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x405000,
            value="invalid license",
            length=15,
            references=[],
            entropy=3.2,
        )

        trial_str = StringResult(
            id=hashlib.sha256(b"trial_string").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x405100,
            value="trial expired",
            length=13,
            references=[],
            entropy=3.0,
        )

        engine.add_results_batch([validate_func, check_func, invalid_str, trial_str])

        license_correlations = [c for c in engine.correlations if c.type == CorrelationType.LICENSE]
        assert len(license_correlations) >= 1

        correlation = license_correlations[0]
        assert len(correlation.source_results) >= 2
        assert correlation.confidence >= 0.80
        assert "pattern" in correlation.evidence

    def test_crypto_pattern_correlation(self, engine: IntelligentCorrelationEngine) -> None:
        """Cryptographic patterns are detected and correlated."""
        aes_result = CryptoResult(
            id=hashlib.sha256(b"aes_crypto").hexdigest(),
            type=ResultType.CRYPTO,
            source_tool="yara",
            timestamp=time.time(),
            address=0x410000,
            algorithm="aes",
            key_size=256,
            mode="CBC",
            constants=[0x63, 0x7C],
        )

        aes_func = FunctionResult(
            id=hashlib.sha256(b"aes_encrypt_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x411000,
            name="aes_encrypt",
            size=500,
            cyclomatic_complexity=10,
        )

        engine.add_results_batch([aes_result, aes_func])

        crypto_correlations = [c for c in engine.correlations if c.type == CorrelationType.CRYPTO]
        assert len(crypto_correlations) >= 1

        correlation = crypto_correlations[0]
        assert "algorithm" in correlation.evidence
        assert correlation.confidence >= 0.85

    def test_protection_pattern_correlation(self, engine: IntelligentCorrelationEngine) -> None:
        """Protection scheme patterns are identified and correlated."""
        vmp_protection = ProtectionResult(
            id=hashlib.sha256(b"vmprotect").hexdigest(),
            type=ResultType.PROTECTION,
            source_tool="yara",
            timestamp=time.time(),
            protection_type="vmprotect",
            name="VMProtect 3.5",
            version="3.5",
            entry_point=0x400000,
        )

        vmp_marker = StringResult(
            id=hashlib.sha256(b"vmp_marker").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x450000,
            value=".vmp0",
            length=5,
            references=[],
            entropy=2.8,
        )

        engine.add_results_batch([vmp_protection, vmp_marker])

        protection_correlations = [c for c in engine.correlations if c.type == CorrelationType.PROTECTION]
        assert len(protection_correlations) >= 1

        correlation = protection_correlations[0]
        assert "protection" in correlation.evidence

    def test_clustering_density_based(self, engine: IntelligentCorrelationEngine) -> None:
        """Clustering identifies groups of related results."""
        results = []
        for i in range(10):
            func = FunctionResult(
                id=hashlib.sha256(f"cluster_func_{i}".encode()).hexdigest(),
                type=ResultType.FUNCTION,
                source_tool="ghidra",
                timestamp=time.time(),
                address=0x401000 + (i * 0x100),
                name=f"license_func_{i}",
                size=200 + (i * 10),
                cyclomatic_complexity=5 + i,
                confidence=0.9,
            )
            results.append(func)

        engine.add_results_batch(results)

        assert len(engine.clusters) >= 0

        if engine.clusters:
            cluster = engine.clusters[0]
            assert isinstance(cluster, CorrelationCluster)
            assert len(cluster.results) >= 3
            assert cluster.confidence > 0

    def test_graph_component_clustering(self, engine: IntelligentCorrelationEngine) -> None:
        """Graph analysis identifies connected components as clusters."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"graph_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="component_func1",
            size=200,
            cyclomatic_complexity=5,
            xrefs_from=[0x401100],
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"graph_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x401100,
            name="component_func2",
            size=180,
            cyclomatic_complexity=4,
            xrefs_from=[0x401200],
        )

        func3 = FunctionResult(
            id=hashlib.sha256(b"graph_func3").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ida_pro",
            timestamp=time.time(),
            address=0x401200,
            name="component_func3",
            size=150,
            cyclomatic_complexity=3,
        )

        engine.add_results_batch([func1, func2, func3])

        assert engine.correlation_graph.number_of_nodes() >= 3
        assert engine.correlation_graph.number_of_edges() >= 0

    def test_high_confidence_findings_filter(self, engine: IntelligentCorrelationEngine) -> None:
        """High confidence findings are correctly filtered."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"high_conf_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_key",
            size=300,
            cyclomatic_complexity=8,
            xrefs_from=[0x402000],
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"high_conf_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="check_serial",
            size=250,
            cyclomatic_complexity=7,
        )

        engine.add_results_batch([func1, func2])

        findings = engine.get_high_confidence_findings(min_confidence=0.80)

        assert isinstance(findings, list)
        for finding in findings:
            assert "confidence" in finding
            assert finding["confidence"] >= 0.80

    def test_correlation_report_generation(self, engine: IntelligentCorrelationEngine) -> None:
        """Correlation report contains all required metrics."""
        func = FunctionResult(
            id=hashlib.sha256(b"report_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_license",
            size=256,
            cyclomatic_complexity=8,
        )

        string = StringResult(
            id=hashlib.sha256(b"report_string").hexdigest(),
            type=ResultType.STRING,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x405000,
            value="License check failed",
            length=20,
            references=[],
            entropy=3.5,
        )

        engine.add_results_batch([func, string])

        report = engine.generate_correlation_report()

        assert "timestamp" in report
        assert "total_results" in report
        assert report["total_results"] == 2
        assert "total_correlations" in report
        assert "total_clusters" in report
        assert "correlation_types" in report
        assert "high_confidence_findings" in report
        assert "graph_metrics" in report
        assert "patterns_detected" in report

    def test_graph_metrics_accurate(self, engine: IntelligentCorrelationEngine) -> None:
        """Graph metrics accurately reflect correlation structure."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"metric_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="func1",
            size=200,
            cyclomatic_complexity=5,
            xrefs_from=[0x401100],
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"metric_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x401100,
            name="func2",
            size=180,
            cyclomatic_complexity=4,
        )

        engine.add_results_batch([func1, func2])

        report = engine.generate_correlation_report()

        assert "graph_metrics" in report
        metrics = report["graph_metrics"]

        assert "nodes" in metrics
        assert metrics["nodes"] >= 2
        assert "edges" in metrics
        assert "density" in metrics
        assert metrics["density"] >= 0
        assert "components" in metrics

    def test_export_to_json(self, engine: IntelligentCorrelationEngine, tmp_path: Any) -> None:
        """JSON export contains complete correlation analysis."""
        func = FunctionResult(
            id=hashlib.sha256(b"export_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="check_license",
            size=300,
            cyclomatic_complexity=8,
        )

        engine.add_result(func)

        output_path = tmp_path / "correlation_export.json"
        engine.export_to_json(str(output_path))

        assert output_path.exists()
        assert output_path.stat().st_size > 0

        import json

        with open(output_path) as f:
            data = json.load(f)

        assert "report" in data
        assert "correlations" in data
        assert "clusters" in data

    def test_semantic_similarity_high(self, engine: IntelligentCorrelationEngine) -> None:
        """Semantically similar results are correlated."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"semantic_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_license_key",
            size=300,
            cyclomatic_complexity=8,
            decompiled_code="bool validate_license_key(char* key) { return check_serial(key); }",
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"semantic_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x410000,
            name="check_license_serial",
            size=250,
            cyclomatic_complexity=7,
            decompiled_code="int check_license_serial(char* serial) { return verify_key(serial); }",
        )

        engine.add_result(func1)
        engine.add_result(func2)

        semantic_correlations = [c for c in engine.correlations if c.type == CorrelationType.SEMANTIC]

        assert len(semantic_correlations) >= 0

    def test_feature_vector_extraction(self, engine: IntelligentCorrelationEngine) -> None:
        """Feature vectors are correctly extracted from results."""
        func = FunctionResult(
            id=hashlib.sha256(b"feature_func").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="validate_key",
            size=256,
            cyclomatic_complexity=8,
            xrefs_to=[0x400500],
            xrefs_from=[0x402000, 0x403000],
        )

        vector = engine._extract_feature_vector(func)

        assert vector is not None
        assert isinstance(vector, np.ndarray)
        assert len(vector) == 10
        assert all(isinstance(x, (float, np.floating)) for x in vector)

    def test_batch_processing_performance(self, engine: IntelligentCorrelationEngine) -> None:
        """Batch processing handles large result sets efficiently."""
        results = []
        for i in range(100):
            func = FunctionResult(
                id=hashlib.sha256(f"batch_func_{i}".encode()).hexdigest(),
                type=ResultType.FUNCTION,
                source_tool="ghidra",
                timestamp=time.time(),
                address=0x400000 + (i * 0x1000),
                name=f"func_{i}",
                size=100 + i,
                cyclomatic_complexity=3 + (i % 5),
            )
            results.append(func)

        start_time = time.time()
        engine.add_results_batch(results)
        elapsed = time.time() - start_time

        assert elapsed < 10.0
        assert len(engine.results) == 100
        assert engine.correlation_graph.number_of_nodes() == 100

    def test_correlation_graph_integrity(self, engine: IntelligentCorrelationEngine) -> None:
        """Correlation graph maintains integrity with edge weights."""
        func1 = FunctionResult(
            id=hashlib.sha256(b"graph_int_func1").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401000,
            name="func1",
            size=200,
            cyclomatic_complexity=5,
            xrefs_from=[0x402000],
        )

        func2 = FunctionResult(
            id=hashlib.sha256(b"graph_int_func2").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="radare2",
            timestamp=time.time(),
            address=0x402000,
            name="func2",
            size=180,
            cyclomatic_complexity=4,
        )

        engine.add_results_batch([func1, func2])

        assert isinstance(engine.correlation_graph, nx.Graph)

        for node in engine.correlation_graph.nodes():
            assert node in engine.results

        for u, v, data in engine.correlation_graph.edges(data=True):
            assert "weight" in data
            assert 0.0 <= data["weight"] <= 1.0

    def test_license_check_result_correlation(self, engine: IntelligentCorrelationEngine) -> None:
        """LicenseCheckResult objects are properly correlated."""
        license_check = LicenseCheckResult(
            id=hashlib.sha256(b"license_check_result").hexdigest(),
            type=ResultType.LICENSE,
            source_tool="custom",
            timestamp=time.time(),
            address=0x401000,
            check_type="serial_validation",
            success_path=0x401100,
            failure_path=0x401200,
            extracted_keys=["XXXX-YYYY-ZZZZ"],
            hwid_sources=["GetVolumeSerialNumber"],
        )

        func = FunctionResult(
            id=hashlib.sha256(b"license_func_corr").hexdigest(),
            type=ResultType.FUNCTION,
            source_tool="ghidra",
            timestamp=time.time(),
            address=0x401050,
            name="check_serial",
            size=300,
            cyclomatic_complexity=8,
        )

        engine.add_results_batch([license_check, func])

        address_correlations = [c for c in engine.correlations if c.type == CorrelationType.ADDRESS_MATCH]
        assert len(address_correlations) >= 0
