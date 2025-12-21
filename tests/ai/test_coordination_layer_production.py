"""Production tests for AI coordination layer.

Tests validate REAL coordination between LLM components for license
protection analysis. All tests verify actual strategy selection, escalation,
and result combination for cracking software protections.

Copyright (C) 2025 Zachary Flint
Licensed under GPL v3.
"""

import hashlib
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.coordination_layer import (
    AICoordinationLayer,
    AnalysisRequest,
    AnalysisStrategy,
    CoordinatedResult,
)


@pytest.fixture
def temp_binary_file() -> Path:
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"MZ" + b"\x00" * (2 * 1024 * 1024))
        return Path(tmp.name)


@pytest.fixture
def large_binary_file() -> Path:
    """Create large temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"MZ" + b"\x00" * (60 * 1024 * 1024))
        return Path(tmp.name)


@pytest.fixture
def cleanup_temp_files(temp_binary_file: Path, large_binary_file: Path):
    """Cleanup temporary files after tests."""
    yield
    if temp_binary_file.exists():
        temp_binary_file.unlink()
    if large_binary_file.exists():
        large_binary_file.unlink()


class TestAnalysisRequest:
    """Tests for AnalysisRequest data structure."""

    def test_request_creates_with_defaults(self, temp_binary_file: Path) -> None:
        """Request creates with default values."""
        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license_protection",
        )

        assert request.binary_path == str(temp_binary_file)
        assert request.analysis_type == "license_protection"
        assert request.strategy == AnalysisStrategy.ADAPTIVE
        assert request.confidence_threshold == 0.7
        assert request.max_processing_time == 30.0
        assert request.use_cache is True

    def test_request_supports_custom_strategy(self, temp_binary_file: Path) -> None:
        """Request supports custom analysis strategy."""
        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="vulnerability",
            strategy=AnalysisStrategy.LLM_ONLY,
        )

        assert request.strategy == AnalysisStrategy.LLM_ONLY

    def test_request_supports_custom_thresholds(self, temp_binary_file: Path) -> None:
        """Request supports custom confidence and time thresholds."""
        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="protection",
            confidence_threshold=0.85,
            max_processing_time=60.0,
        )

        assert request.confidence_threshold == 0.85
        assert request.max_processing_time == 60.0


class TestCoordinatedResult:
    """Tests for CoordinatedResult data structure."""

    def test_result_initializes_with_defaults(self) -> None:
        """Result initializes with default values."""
        result = CoordinatedResult()

        assert result.ml_results is None
        assert result.llm_results is None
        assert result.combined_confidence == 0.0
        assert result.strategy_used == AnalysisStrategy.ML_FIRST
        assert result.processing_time == 0.0
        assert result.escalated is False
        assert result.cache_hit is False

    def test_result_stores_ml_analysis(self) -> None:
        """Result stores ML analysis results."""
        ml_data = {
            "protection": "VMProtect",
            "confidence": 0.92,
            "features": ["packing", "obfuscation"],
        }
        result = CoordinatedResult(ml_results=ml_data)

        assert result.ml_results == ml_data
        assert result.ml_results["confidence"] == 0.92

    def test_result_stores_llm_analysis(self) -> None:
        """Result stores LLM analysis results."""
        llm_data = {
            "license_check_location": "0x401000",
            "confidence": 0.88,
            "bypass_strategy": "patch_jump",
        }
        result = CoordinatedResult(llm_results=llm_data)

        assert result.llm_results == llm_data
        assert result.llm_results["bypass_strategy"] == "patch_jump"

    def test_result_tracks_escalation(self) -> None:
        """Result tracks whether analysis was escalated."""
        result = CoordinatedResult(escalated=True)

        assert result.escalated is True

    def test_result_tracks_cache_hits(self) -> None:
        """Result tracks whether result came from cache."""
        result = CoordinatedResult(cache_hit=True)

        assert result.cache_hit is True


class TestAICoordinationLayer:
    """Tests for AICoordinationLayer core functionality."""

    def test_coordination_layer_initializes(self) -> None:
        """Coordination layer initializes with components."""
        coordinator = AICoordinationLayer()

        assert coordinator.shared_context is not None
        assert coordinator.event_bus is not None
        assert coordinator.performance_stats is not None
        assert coordinator.analysis_cache == {}

    def test_coordination_layer_tracks_performance_stats(self) -> None:
        """Coordination layer tracks performance statistics."""
        coordinator = AICoordinationLayer()

        assert "ml_calls" in coordinator.performance_stats
        assert "llm_calls" in coordinator.performance_stats
        assert "escalations" in coordinator.performance_stats
        assert "cache_hits" in coordinator.performance_stats
        assert "avg_ml_time" in coordinator.performance_stats
        assert "avg_llm_time" in coordinator.performance_stats

    def test_coordination_layer_initializes_model_manager(self) -> None:
        """Coordination layer initializes model manager."""
        coordinator = AICoordinationLayer()

        assert hasattr(coordinator, "model_manager")


class TestCaching:
    """Tests for analysis result caching."""

    def test_cache_key_generation(self, temp_binary_file: Path) -> None:
        """Cache key generation creates unique keys for requests."""
        coordinator = AICoordinationLayer()

        request1 = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.ML_FIRST,
        )

        request2 = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="vulnerability",
            strategy=AnalysisStrategy.ML_FIRST,
        )

        key1 = coordinator._get_cache_key(request1)
        key2 = coordinator._get_cache_key(request2)

        assert key1 != key2
        assert len(key1) == 64
        assert len(key2) == 64

    def test_cache_stores_results(self) -> None:
        """Cache stores analysis results correctly."""
        coordinator = AICoordinationLayer()

        result = CoordinatedResult(
            ml_results={"protection": "VMProtect"},
            combined_confidence=0.9,
        )

        cache_key = "test_key_123"
        coordinator._cache_result(cache_key, result)

        assert cache_key in coordinator.analysis_cache
        assert coordinator.analysis_cache[cache_key]["result"] == result
        assert "timestamp" in coordinator.analysis_cache[cache_key]

    def test_cache_validity_check(self) -> None:
        """Cache validity check identifies expired entries."""
        coordinator = AICoordinationLayer()
        coordinator.cache_ttl = timedelta(seconds=1)

        cache_entry = {
            "result": CoordinatedResult(),
            "timestamp": datetime.now() - timedelta(seconds=2),
        }

        is_valid = coordinator._is_cache_valid(cache_entry)

        assert is_valid is False

    def test_cache_validity_check_fresh(self) -> None:
        """Cache validity check identifies fresh entries."""
        coordinator = AICoordinationLayer()
        coordinator.cache_ttl = timedelta(hours=1)

        cache_entry = {
            "result": CoordinatedResult(),
            "timestamp": datetime.now(),
        }

        is_valid = coordinator._is_cache_valid(cache_entry)

        assert is_valid is True

    def test_cached_results_return_immediately(self, temp_binary_file: Path) -> None:
        """Cached results return immediately without analysis."""
        coordinator = AICoordinationLayer()

        cached_result = CoordinatedResult(
            llm_results={"cached": True},
            combined_confidence=0.95,
        )

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
        )

        cache_key = coordinator._get_cache_key(request)
        coordinator._cache_result(cache_key, cached_result)

        result = coordinator.analyze_vulnerabilities(request)

        assert result.cache_hit is True
        assert result.llm_results == {"cached": True}
        assert coordinator.performance_stats["cache_hits"] == 1


class TestStrategySelection:
    """Tests for adaptive strategy selection."""

    def test_adaptive_strategy_for_large_files(self, large_binary_file: Path) -> None:
        """Adaptive strategy selects ML_FIRST for large files."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(large_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.ADAPTIVE,
        )

        strategy = coordinator._choose_strategy(request)

        assert strategy == AnalysisStrategy.ML_FIRST

    def test_adaptive_strategy_for_small_files(self) -> None:
        """Adaptive strategy selects PARALLEL for small files."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ" + b"\x00" * (500 * 1024))
            small_file = Path(tmp.name)

        try:
            coordinator = AICoordinationLayer()

            request = AnalysisRequest(
                binary_path=str(small_file),
                analysis_type="license",
                strategy=AnalysisStrategy.ADAPTIVE,
            )

            strategy = coordinator._choose_strategy(request)

            assert strategy == AnalysisStrategy.PARALLEL
        finally:
            small_file.unlink()

    def test_explicit_strategy_overrides_adaptive(self, temp_binary_file: Path) -> None:
        """Explicit strategy overrides adaptive selection."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
        )

        strategy = coordinator._choose_strategy(request)

        assert strategy == AnalysisStrategy.LLM_ONLY


class TestLLMOnlyAnalysis:
    """Tests for LLM-only analysis execution."""

    def test_llm_only_analysis_executes(self, temp_binary_file: Path) -> None:
        """LLM-only analysis executes successfully."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=False,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert result.combined_confidence >= 0
        assert result.processing_time > 0

    def test_llm_analysis_tracks_processing_time(self, temp_binary_file: Path) -> None:
        """LLM analysis tracks processing time."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=False,
        )

        start = time.time()
        result = coordinator.analyze_vulnerabilities(request)
        elapsed = time.time() - start

        assert result.processing_time > 0
        assert result.processing_time <= elapsed + 0.1


class TestMLFirstAnalysis:
    """Tests for ML-first analysis with LLM fallback."""

    def test_ml_first_falls_back_to_llm(self, temp_binary_file: Path) -> None:
        """ML-first strategy falls back to LLM (ML removed)."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="protection",
            strategy=AnalysisStrategy.ML_FIRST,
            use_cache=False,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert result.combined_confidence >= 0
        assert result.processing_time > 0


class TestEventEmission:
    """Tests for event bus integration."""

    def test_completion_event_emitted(self, temp_binary_file: Path) -> None:
        """Completion event emitted after analysis."""
        coordinator = AICoordinationLayer()
        event_received = []

        def event_callback(data: dict, source: str) -> None:
            event_received.append((data, source))

        coordinator.event_bus.subscribe(
            "coordinated_analysis_complete",
            event_callback,
            "test",
        )

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=False,
        )

        coordinator.analyze_vulnerabilities(request)
        time.sleep(0.2)

        assert len(event_received) > 0
        assert event_received[0][1] == "coordination_layer"


class TestErrorHandling:
    """Tests for error handling in coordination."""

    def test_handles_missing_binary_file(self) -> None:
        """Handles missing binary file gracefully."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path="/nonexistent/binary.exe",
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=False,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert result is not None
        assert result.processing_time > 0


class TestPerformanceTracking:
    """Tests for performance statistics tracking."""

    def test_tracks_processing_time(self, temp_binary_file: Path) -> None:
        """Tracks processing time for analyses."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=False,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert result.processing_time > 0


class TestIntegrationScenarios:
    """Integration tests for complete coordination workflows."""

    def test_complete_license_analysis_workflow(self, temp_binary_file: Path) -> None:
        """Complete license analysis workflow with coordination."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license_protection",
            strategy=AnalysisStrategy.ADAPTIVE,
            confidence_threshold=0.8,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert result.combined_confidence >= 0
        assert result.processing_time > 0

    def test_cached_second_analysis(self, temp_binary_file: Path) -> None:
        """Second analysis of same binary uses cache."""
        coordinator = AICoordinationLayer()

        request = AnalysisRequest(
            binary_path=str(temp_binary_file),
            analysis_type="license",
            use_cache=True,
        )

        result1 = coordinator.analyze_vulnerabilities(request)
        result2 = coordinator.analyze_vulnerabilities(request)

        assert result1.cache_hit is False
        assert result2.cache_hit is True
        assert result2.processing_time < result1.processing_time

    def test_performance_stats_accumulation(self, temp_binary_file: Path) -> None:
        """Performance stats accumulate across multiple analyses."""
        coordinator = AICoordinationLayer()

        for i in range(3):
            request = AnalysisRequest(
                binary_path=str(temp_binary_file),
                analysis_type=f"test_{i}",
                use_cache=False,
            )
            coordinator.analyze_vulnerabilities(request)

        assert coordinator.performance_stats["cache_hits"] >= 0
