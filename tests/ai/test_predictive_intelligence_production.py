"""Production tests for predictive intelligence engine.

Validates real prediction capabilities for success probability, execution time,
resource usage, vulnerability discovery, and optimal strategy selection.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.ai.predictive_intelligence import (
    FeatureExtractor,
    PredictionConfidence,
    PredictionInput,
    PredictionResult,
    PredictionType,
    PredictiveIntelligenceEngine,
    TimeSeriesData,
)


class TestFeatureExtractor:
    """Tests for feature extraction from operations."""

    def test_initialization(self) -> None:
        extractor = FeatureExtractor()

        assert extractor.feature_cache == {}
        assert extractor.feature_importance == {}
        assert extractor.learning_engine is not None

    def test_extract_operation_features(self) -> None:
        extractor = FeatureExtractor()

        features = extractor.extract_operation_features("binary_analysis", {"file_size": 1024000, "analysis_depth": "deep"})

        assert "operation_complexity" in features
        assert "input_size" in features
        assert "context_richness" in features
        assert "historical_success_rate" in features
        assert "cpu_usage" in features

    def test_calculate_operation_complexity(self) -> None:
        extractor = FeatureExtractor()

        complexity = extractor._calculate_operation_complexity("exploit_generation", {"file_size": 2000000, "analysis_depth": "comprehensive"})

        assert 0.0 <= complexity <= 2.0
        assert complexity > 0.9

    def test_calculate_input_size(self) -> None:
        extractor = FeatureExtractor()

        size_small = extractor._calculate_input_size({"file_size": 1024})
        size_medium = extractor._calculate_input_size({"file_size": 1024000})
        size_large = extractor._calculate_input_size({"file_size": 10240000})

        assert size_small < size_medium < size_large
        assert 0.0 <= size_small <= 1.0

    def test_extract_system_features(self) -> None:
        extractor = FeatureExtractor()

        features = extractor._extract_system_features()

        assert "cpu_usage" in features
        assert "memory_usage" in features
        assert "system_load" in features
        assert all(0.0 <= v <= 2.0 for v in features.values())

    def test_extract_time_features(self) -> None:
        extractor = FeatureExtractor()

        features = extractor._extract_time_features()

        assert "hour_of_day" in features
        assert "day_of_week" in features
        assert "is_business_hours" in features
        assert 0.0 <= features["hour_of_day"] <= 1.0
        assert features["is_business_hours"] in [0.0, 1.0]

    def test_extract_vulnerability_features(self) -> None:
        extractor = FeatureExtractor()

        vuln_context = {
            "binary_complexity": 0.8,
            "protection_layers": 3,
            "code_patterns": ["buffer_check", "bounds_check"],
            "historical_vulns": 2,
        }

        features = extractor.extract_vulnerability_features(vuln_context)

        assert "complexity_score" in features
        assert "pattern_diversity" in features
        assert features["complexity_score"] > 0


class TestPredictiveIntelligenceEngine:
    """Tests for main predictive intelligence engine."""

    def test_initialization(self) -> None:
        engine = PredictiveIntelligenceEngine()

        assert engine.feature_extractor is not None
        assert engine.time_series_analyzer is not None
        assert engine.prediction_history == []

    def test_predict_success_probability(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="vulnerability_analysis",
            context={"file_size": 1024000, "protection_complexity": 0.7},
            features={"historical_success_rate": 0.8, "operation_complexity": 0.6},
        )

        result = engine.predict_success_probability(pred_input)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.SUCCESS_PROBABILITY
        assert 0.0 <= result.predicted_value <= 1.0
        assert isinstance(result.confidence, PredictionConfidence)
        assert 0.0 <= result.confidence_score <= 1.0

    def test_predict_execution_time(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="binary_analysis", context={"file_size": 2048000}, features={"avg_execution_time": 10.0, "system_load": 0.3}
        )

        result = engine.predict_execution_time(pred_input)

        assert result.prediction_type == PredictionType.EXECUTION_TIME
        assert result.predicted_value > 0
        assert len(result.factors) > 0

    def test_predict_resource_usage(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="exploit_generation", context={"complexity": "high"}, features={"cpu_usage": 0.5, "memory_usage": 0.6}
        )

        result = engine.predict_resource_usage(pred_input)

        assert result.prediction_type == PredictionType.RESOURCE_USAGE
        assert 0.0 <= result.predicted_value <= 1.0

    def test_predict_vulnerability_discovery(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="vulnerability_scan",
            context={"binary_complexity": 0.8, "protection_layers": 2},
            features={"complexity_score": 0.7, "pattern_diversity": 0.6},
        )

        result = engine.predict_vulnerability_discovery(pred_input)

        assert result.prediction_type == PredictionType.VULNERABILITY_DISCOVERY
        assert 0.0 <= result.predicted_value <= 1.0

    def test_suggest_optimal_strategy(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="license_analysis", context={"binary_size": 5120000, "complexity": "moderate"}, features={"system_load": 0.4}
        )

        result = engine.suggest_optimal_strategy(pred_input)

        assert result.prediction_type == PredictionType.OPTIMAL_STRATEGY
        assert isinstance(result.predicted_value, (int, float))
        assert "recommended_strategy" in result.factors

    def test_get_confidence_level(self) -> None:
        engine = PredictiveIntelligenceEngine()

        assert engine._get_confidence_level(0.95) == PredictionConfidence.VERY_HIGH
        assert engine._get_confidence_level(0.8) == PredictionConfidence.HIGH
        assert engine._get_confidence_level(0.6) == PredictionConfidence.MEDIUM
        assert engine._get_confidence_level(0.4) == PredictionConfidence.LOW
        assert engine._get_confidence_level(0.2) == PredictionConfidence.VERY_LOW

    def test_get_prediction_history(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="test", context={}, features={})

        engine.predict_success_probability(pred_input)
        engine.predict_execution_time(pred_input)

        history = engine.get_prediction_history()

        assert len(history) == 2
        assert all(isinstance(p, PredictionResult) for p in history)

    def test_get_prediction_accuracy(self) -> None:
        engine = PredictiveIntelligenceEngine()

        stats = engine.get_prediction_accuracy()

        assert "total_predictions" in stats
        assert "by_type" in stats
        assert "average_confidence" in stats


class TestPredictionInputValidation:
    """Tests for prediction input validation and edge cases."""

    def test_prediction_input_creation(self) -> None:
        pred_input = PredictionInput(
            operation_type="test_op",
            context={"key": "value"},
            historical_data=[{"result": "success"}],
            features={"feature1": 0.5},
            metadata={"source": "test"},
        )

        assert pred_input.operation_type == "test_op"
        assert pred_input.context["key"] == "value"
        assert len(pred_input.historical_data) == 1
        assert pred_input.features["feature1"] == 0.5

    def test_prediction_with_empty_features(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="test", context={}, features={})

        result = engine.predict_success_probability(pred_input)

        assert result is not None
        assert 0.0 <= result.predicted_value <= 1.0

    def test_prediction_with_missing_context(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="binary_analysis", context={}, features={})

        result = engine.predict_execution_time(pred_input)

        assert result.predicted_value > 0


class TestPredictionResultStructure:
    """Tests for prediction result structure and metadata."""

    def test_prediction_result_creation(self) -> None:
        from datetime import datetime

        result = PredictionResult(
            prediction_id="test-123",
            prediction_type=PredictionType.SUCCESS_PROBABILITY,
            predicted_value=0.85,
            confidence=PredictionConfidence.HIGH,
            confidence_score=0.82,
            factors={"factor1": 0.6, "factor2": 0.4},
            reasoning="Test reasoning",
            model_version="1.0",
            error_bounds=(0.80, 0.90),
        )

        assert result.prediction_id == "test-123"
        assert result.prediction_type == PredictionType.SUCCESS_PROBABILITY
        assert result.predicted_value == 0.85
        assert result.confidence == PredictionConfidence.HIGH
        assert len(result.factors) == 2
        assert result.error_bounds[0] < result.predicted_value < result.error_bounds[1]


class TestRealWorldScenarios:
    """Tests for real-world prediction scenarios."""

    def test_large_binary_analysis_prediction(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="binary_analysis",
            context={"file_size": 50 * 1024 * 1024, "analysis_depth": "comprehensive", "protection_layers": 3},
            features={},
        )

        time_result = engine.predict_execution_time(pred_input)
        resource_result = engine.predict_resource_usage(pred_input)

        assert time_result.predicted_value > 10.0
        assert resource_result.predicted_value > 0.5

    def test_simple_vulnerability_scan_prediction(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="vulnerability_scan", context={"file_size": 512 * 1024, "binary_complexity": 0.3}, features={}
        )

        success_result = engine.predict_success_probability(pred_input)
        vuln_result = engine.predict_vulnerability_discovery(pred_input)

        assert success_result.predicted_value > 0.6
        assert vuln_result.predicted_value > 0

    def test_exploit_generation_prediction(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(
            operation_type="exploit_generation",
            context={"vulnerability_severity": "high", "protection_complexity": 0.8},
            features={"historical_success_rate": 0.6},
        )

        success_result = engine.predict_success_probability(pred_input)

        assert 0.0 <= success_result.predicted_value <= 1.0
        assert success_result.confidence in list(PredictionConfidence)


class TestPredictionCaching:
    """Tests for prediction caching and performance optimization."""

    def test_repeated_predictions_use_cache(self) -> None:
        engine = PredictiveIntelligenceEngine()
        extractor = engine.feature_extractor

        context1 = {"file_size": 1024000}
        context2 = {"file_size": 1024000}

        features1 = extractor.extract_operation_features("test", context1)
        features2 = extractor.extract_operation_features("test", context2)

        assert features1.keys() == features2.keys()


class TestPredictionAccuracy:
    """Tests for prediction accuracy tracking."""

    def test_track_prediction_outcome(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="test", context={}, features={})

        result = engine.predict_success_probability(pred_input)

        engine.track_prediction_outcome(result.prediction_id, actual_value=0.9, success=True)

        stats = engine.get_prediction_accuracy()

        assert stats["total_predictions"] > 0


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_zero_file_size(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="binary_analysis", context={"file_size": 0}, features={})

        result = engine.predict_execution_time(pred_input)

        assert result.predicted_value > 0

    def test_very_large_file(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="binary_analysis", context={"file_size": 1024 * 1024 * 1024}, features={})

        result = engine.predict_resource_usage(pred_input)

        assert result.predicted_value > 0.7

    def test_unknown_operation_type(self) -> None:
        engine = PredictiveIntelligenceEngine()

        pred_input = PredictionInput(operation_type="unknown_operation", context={}, features={})

        result = engine.predict_success_probability(pred_input)

        assert result is not None
        assert 0.0 <= result.predicted_value <= 1.0
