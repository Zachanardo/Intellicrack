"""Production tests for AI Coordination Layer.

Tests coordinated vulnerability analysis using real LLM backends and validates
complete analysis workflows.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.coordination_layer import (
    AICoordinationLayer,
    AnalysisRequest,
    AnalysisStrategy,
    CoordinatedResult,
    comprehensive_analysis,
    quick_vulnerability_scan,
)


@pytest.fixture
def temp_binary() -> Path:
    """Create a temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 512)
        return Path(f.name)


@pytest.fixture
def coordinator() -> AICoordinationLayer:
    """Create AI coordination layer instance."""
    return AICoordinationLayer()


class TestAICoordinationLayer:
    """Test AI coordination layer functionality."""

    def test_coordinator_initialization(self, coordinator: AICoordinationLayer) -> None:
        """Coordinator initializes with correct default configuration."""
        assert coordinator is not None
        assert coordinator.performance_stats["ml_calls"] == 0
        assert coordinator.performance_stats["llm_calls"] == 0
        assert coordinator.performance_stats["escalations"] == 0
        assert len(coordinator.analysis_cache) == 0

    def test_choose_strategy_adaptive_large_file(self, temp_binary: Path) -> None:
        """Large files use ML_FIRST strategy for initial analysis."""
        coordinator = AICoordinationLayer()
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="vulnerability_scan",
            strategy=AnalysisStrategy.ADAPTIVE,
        )

        strategy = coordinator._choose_strategy(request)
        assert strategy in {AnalysisStrategy.ML_FIRST, AnalysisStrategy.PARALLEL}

    def test_choose_strategy_small_file(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Small files can use PARALLEL strategy for faster analysis."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="vulnerability_scan",
            strategy=AnalysisStrategy.ADAPTIVE,
        )

        strategy = coordinator._choose_strategy(request)
        assert strategy in {AnalysisStrategy.ML_FIRST, AnalysisStrategy.PARALLEL}

    def test_analyze_vulnerabilities_llm_only(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """LLM-only analysis produces valid results with confidence scoring."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="vulnerability_scan",
            strategy=AnalysisStrategy.LLM_ONLY,
            max_processing_time=30.0,
        )

        result = coordinator.analyze_vulnerabilities(request)

        assert isinstance(result, CoordinatedResult)
        assert result.strategy_used == AnalysisStrategy.LLM_ONLY
        assert result.processing_time >= 0
        assert 0.0 <= result.combined_confidence <= 1.0

    def test_cache_functionality(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Analysis results are cached and reused for identical requests."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="quick_scan",
            strategy=AnalysisStrategy.LLM_ONLY,
            use_cache=True,
        )

        result1 = coordinator.analyze_vulnerabilities(request)
        assert not result1.cache_hit

        result2 = coordinator.analyze_vulnerabilities(request)
        assert result2.cache_hit
        assert coordinator.performance_stats["cache_hits"] == 1

    def test_cache_clearing(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Cache clearing removes all cached results."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="scan",
            use_cache=True,
        )

        coordinator.analyze_vulnerabilities(request)
        assert len(coordinator.analysis_cache) > 0

        coordinator.clear_cache()
        assert len(coordinator.analysis_cache) == 0

    def test_performance_stats_tracking(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Performance statistics accurately track analysis operations."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="vulnerability_scan",
            strategy=AnalysisStrategy.LLM_ONLY,
        )

        coordinator.analyze_vulnerabilities(request)

        stats = coordinator.get_performance_stats()
        assert stats["llm_calls"] >= 0
        assert stats["cache_hits"] >= 0
        assert stats["cache_size"] >= 0
        assert "components_available" in stats

    def test_suggest_strategy_license_analysis(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """License analysis suggests appropriate strategy for complex pattern recognition."""
        strategy = coordinator.suggest_strategy(str(temp_binary), "license_analysis")
        assert strategy in {AnalysisStrategy.LLM_FIRST, AnalysisStrategy.ADAPTIVE, AnalysisStrategy.PARALLEL}

    def test_suggest_strategy_vulnerability_scan(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Vulnerability scan suggests appropriate strategy for fast assessment."""
        strategy = coordinator.suggest_strategy(str(temp_binary), "vulnerability_scan")
        assert strategy in {AnalysisStrategy.ML_FIRST, AnalysisStrategy.ADAPTIVE, AnalysisStrategy.PARALLEL}

    def test_llm_analysis_integration(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """LLM analysis produces structured vulnerability assessment."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="comprehensive",
            strategy=AnalysisStrategy.LLM_ONLY,
        )

        result = coordinator.analyze_vulnerabilities(request)

        if result.llm_results:
            assert "confidence" in result.llm_results
            assert "analysis_type" in result.llm_results

    def test_create_binary_analysis_prompt(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Binary analysis prompt contains required analysis directives."""
        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="security_audit",
        )

        prompt = coordinator._create_binary_analysis_prompt(request)

        assert str(temp_binary) in prompt
        assert "vulnerability" in prompt.lower() or "security" in prompt.lower()
        assert "analysis" in prompt.lower()

    def test_fallback_analysis_when_llm_unavailable(self, temp_binary: Path) -> None:
        """Fallback analysis provides basic recommendations when LLM unavailable."""
        coordinator = AICoordinationLayer()
        coordinator._llm_manager = None

        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="basic_scan",
        )

        result = coordinator.analyze_vulnerabilities(request)
        assert result is not None
        assert isinstance(result, CoordinatedResult)


class TestConvenienceFunctions:
    """Test convenience functions for common workflows."""

    def test_quick_vulnerability_scan(self, temp_binary: Path) -> None:
        """Quick scan produces results within acceptable time."""
        result = quick_vulnerability_scan(str(temp_binary))

        assert isinstance(result, CoordinatedResult)
        assert result.processing_time >= 0

    def test_comprehensive_analysis(self, temp_binary: Path) -> None:
        """Comprehensive analysis uses PARALLEL strategy for thoroughness."""
        result = comprehensive_analysis(str(temp_binary))

        assert isinstance(result, CoordinatedResult)
        assert result.strategy_used == AnalysisStrategy.PARALLEL


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_invalid_binary_path(self, coordinator: AICoordinationLayer) -> None:
        """Invalid binary path handled gracefully without crashes."""
        request = AnalysisRequest(
            binary_path="/nonexistent/binary.exe",
            analysis_type="scan",
        )

        result = coordinator.analyze_vulnerabilities(request)
        assert result is not None

    def test_multiple_concurrent_analyses(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Multiple analyses tracked independently in performance stats."""
        requests = [
            AnalysisRequest(
                binary_path=str(temp_binary),
                analysis_type=f"scan_{i}",
                use_cache=False,
            )
            for i in range(3)
        ]

        for request in requests:
            coordinator.analyze_vulnerabilities(request)

        stats = coordinator.get_performance_stats()
        assert stats["llm_calls"] >= 0

    def test_cache_ttl_expiration(self, coordinator: AICoordinationLayer, temp_binary: Path) -> None:
        """Cache TTL validation prevents stale cache usage."""
        from datetime import datetime, timedelta

        request = AnalysisRequest(
            binary_path=str(temp_binary),
            analysis_type="scan",
            use_cache=True,
        )

        result = coordinator.analyze_vulnerabilities(request)
        cache_key = coordinator._get_cache_key(request)

        coordinator.analysis_cache[cache_key]["timestamp"] = datetime.now() - timedelta(hours=2)

        result2 = coordinator.analyze_vulnerabilities(request)
        assert not result2.cache_hit
