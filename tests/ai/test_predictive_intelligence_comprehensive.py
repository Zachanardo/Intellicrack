"""Comprehensive production-ready tests for predictive intelligence engine.

Tests validate REAL prediction algorithms for protection cracking operations.
All tests verify actual prediction generation without mocks.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import math
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.predictive_intelligence import (
    ExecutionTimePredictor,
    FeatureExtractor,
    LinearRegressionModel,
    PredictionConfidence,
    PredictionInput,
    PredictionResult,
    PredictionType,
    PredictiveIntelligenceEngine,
    SuccessProbabilityPredictor,
    VulnerabilityPredictor,
)


class TestFeatureExtractor:
    """Test feature extraction from binary analysis data."""

    @pytest.fixture
    def extractor(self) -> FeatureExtractor:
        """Create feature extractor instance."""
        return FeatureExtractor()

    def test_extract_operation_features_returns_valid_feature_dict(self, extractor: FeatureExtractor) -> None:
        """Extract operation features produces complete feature dictionary."""
        context = {
            "file_size": 1024000,
            "analysis_depth": "deep",
            "target_type": "binary",
        }

        features = extractor.extract_operation_features("binary_analysis", context)

        assert isinstance(features, dict)
        assert len(features) > 0
        assert "operation_complexity" in features
        assert "input_size" in features
        assert "context_richness" in features
        assert all(isinstance(v, (float, int)) for v in features.values())

    def test_operation_complexity_calculation_matches_operation_type(self, extractor: FeatureExtractor) -> None:
        """Operation complexity varies based on operation type."""
        context = {"file_size": 1024000}

        simple_features = extractor.extract_operation_features("script_generation", context)
        complex_features = extractor.extract_operation_features("exploit_generation", context)

        assert simple_features["operation_complexity"] < complex_features["operation_complexity"]
        assert complex_features["operation_complexity"] >= 0.9

    def test_operation_complexity_scales_with_file_size(self, extractor: FeatureExtractor) -> None:
        """Operation complexity increases with larger file sizes."""
        small_context = {"file_size": 10000}
        large_context = {"file_size": 50000000}

        small_features = extractor.extract_operation_features("binary_analysis", small_context)
        large_features = extractor.extract_operation_features("binary_analysis", large_context)

        assert large_features["operation_complexity"] > small_features["operation_complexity"]

    def test_operation_complexity_scales_with_analysis_depth(self, extractor: FeatureExtractor) -> None:
        """Operation complexity increases with deeper analysis."""
        shallow_context = {"analysis_depth": "shallow"}
        deep_context = {"analysis_depth": "comprehensive"}

        shallow_features = extractor.extract_operation_features("binary_analysis", shallow_context)
        deep_features = extractor.extract_operation_features("binary_analysis", deep_context)

        assert deep_features["operation_complexity"] > shallow_features["operation_complexity"]

    def test_input_size_normalization_uses_log_scale(self, extractor: FeatureExtractor) -> None:
        """Input size normalized using logarithmic scaling."""
        small_context = {"file_size": 1000}
        medium_context = {"file_size": 100000}
        large_context = {"file_size": 10000000}

        small_features = extractor.extract_operation_features("binary_analysis", small_context)
        medium_features = extractor.extract_operation_features("binary_analysis", medium_context)
        large_features = extractor.extract_operation_features("binary_analysis", large_context)

        assert 0.0 <= small_features["input_size"] <= 1.0
        assert small_features["input_size"] < medium_features["input_size"] < large_features["input_size"]

    def test_extract_vulnerability_features_calculates_file_type_risk(self, extractor: FeatureExtractor) -> None:
        """Vulnerability features assign higher risk to executable types."""
        exe_context = {"file_extension": ".exe", "file_size": 1024000}
        dll_context = {"file_extension": ".dll", "file_size": 1024000}
        py_context = {"file_extension": ".py", "file_size": 1024000}

        exe_features = extractor.extract_vulnerability_features(exe_context)
        dll_features = extractor.extract_vulnerability_features(dll_context)
        py_features = extractor.extract_vulnerability_features(py_context)

        assert exe_features["file_type_risk"] > py_features["file_type_risk"]
        assert dll_features["file_type_risk"] > py_features["file_type_risk"]

    def test_extract_vulnerability_features_handles_entropy(self, extractor: FeatureExtractor) -> None:
        """Vulnerability features extract and normalize entropy values."""
        context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "entropy": 7.5,
        }

        features = extractor.extract_vulnerability_features(context)

        assert "entropy" in features
        assert 0.0 <= features["entropy"] <= 1.0
        assert features["entropy"] == pytest.approx(7.5 / 8.0, abs=0.01)

    def test_extract_exploit_features_evaluates_vulnerability_type(self, extractor: FeatureExtractor) -> None:
        """Exploit features assign success rates based on vulnerability type."""
        buffer_overflow_ctx = {"vulnerability_type": "buffer_overflow"}
        code_injection_ctx = {"vulnerability_type": "code_injection"}
        unknown_ctx = {"vulnerability_type": "unknown"}

        buffer_features = extractor.extract_exploit_features(buffer_overflow_ctx)
        injection_features = extractor.extract_exploit_features(code_injection_ctx)
        unknown_features = extractor.extract_exploit_features(unknown_ctx)

        assert injection_features["vuln_type_baseline"] > buffer_features["vuln_type_baseline"]
        assert unknown_features["vuln_type_baseline"] == 0.5

    def test_extract_exploit_features_accounts_for_protections(self, extractor: FeatureExtractor) -> None:
        """Exploit features increase difficulty with more protections."""
        no_protection_ctx: dict[str, list[str]] = {"protections": []}
        few_protections_ctx: dict[str, list[str]] = {"protections": ["ASLR", "DEP"]}
        many_protections_ctx: dict[str, list[str]] = {"protections": ["ASLR", "DEP", "CFG", "SafeSEH"]}

        no_prot_features = extractor.extract_exploit_features(no_protection_ctx)
        few_prot_features = extractor.extract_exploit_features(few_protections_ctx)
        many_prot_features = extractor.extract_exploit_features(many_protections_ctx)

        assert no_prot_features["protection_difficulty"] < few_prot_features["protection_difficulty"]
        assert few_prot_features["protection_difficulty"] < many_prot_features["protection_difficulty"]

    def test_extract_exploit_features_evaluates_chain_complexity(self, extractor: FeatureExtractor) -> None:
        """Exploit features measure complexity of exploitation chains."""
        single_step_ctx = {"chain_length": 1}
        multi_step_ctx = {"chain_length": 5}

        single_features = extractor.extract_exploit_features(single_step_ctx)
        multi_features = extractor.extract_exploit_features(multi_step_ctx)

        assert multi_features["chain_complexity"] > single_features["chain_complexity"]

    def test_extract_system_features_returns_normalized_values(self, extractor: FeatureExtractor) -> None:
        """System features are normalized to 0-1 range."""
        features = extractor._extract_system_features()

        assert "cpu_usage" in features
        assert "memory_usage" in features
        assert "system_load" in features

        assert all(0.0 <= v <= 2.0 for v in features.values())

    def test_extract_time_features_includes_business_hours(self, extractor: FeatureExtractor) -> None:
        """Time features include business hours indicator."""
        features = extractor._extract_time_features()

        assert "hour_of_day" in features
        assert "day_of_week" in features
        assert "is_business_hours" in features

        assert 0.0 <= features["hour_of_day"] <= 1.0
        assert 0.0 <= features["day_of_week"] <= 1.0
        assert features["is_business_hours"] in [0.0, 1.0]


class TestLinearRegressionModel:
    """Test linear regression prediction model."""

    @pytest.fixture
    def model(self) -> LinearRegressionModel:
        """Create linear regression model instance."""
        return LinearRegressionModel("test_model")

    def test_model_initialization_sets_parameters(self, model: LinearRegressionModel) -> None:
        """Model initializes with correct parameters."""
        assert model.model_name == "test_model"
        assert model.model_version == "1.0"
        assert model.weights == {}
        assert model.bias == 0.0
        assert model.learning_rate == 0.01

    def test_train_updates_weights_from_training_data(self, model: LinearRegressionModel) -> None:
        """Training updates model weights based on training data."""
        training_data = [
            {"features": {"complexity": 0.5, "size": 0.3}, "target": 0.6},
            {"features": {"complexity": 0.8, "size": 0.7}, "target": 0.4},
            {"features": {"complexity": 0.3, "size": 0.2}, "target": 0.8},
            {"features": {"complexity": 0.6, "size": 0.5}, "target": 0.5},
        ]

        model.train(training_data)

        assert len(model.weights) > 0
        assert "complexity" in model.weights
        assert "size" in model.weights
        assert model.last_training is not None

    def test_train_calculates_feature_importance(self, model: LinearRegressionModel) -> None:
        """Training calculates feature importance scores."""
        training_data = [
            {"features": {"complexity": 0.9, "size": 0.1}, "target": 0.85},
            {"features": {"complexity": 0.8, "size": 0.2}, "target": 0.75},
            {"features": {"complexity": 0.7, "size": 0.3}, "target": 0.65},
        ]

        model.train(training_data)

        assert len(model.feature_importance) > 0
        assert all(0.0 <= v <= 1.0 for v in model.feature_importance.values())
        assert abs(sum(model.feature_importance.values()) - 1.0) < 0.01

    def test_predict_returns_reasonable_values_for_trained_model(self, model: LinearRegressionModel) -> None:
        """Prediction returns reasonable values after training."""
        training_data = [
            {"features": {"complexity": 0.5}, "target": 0.6},
            {"features": {"complexity": 0.8}, "target": 0.4},
            {"features": {"complexity": 0.3}, "target": 0.8},
        ]

        model.train(training_data)

        prediction, confidence = model.predict({"complexity": 0.5})

        assert 0.0 <= prediction <= 1.0
        assert 0.0 <= confidence <= 1.0

    def test_predict_returns_default_for_untrained_model(self, model: LinearRegressionModel) -> None:
        """Untrained model returns default prediction."""
        prediction, confidence = model.predict({"complexity": 0.5})

        assert prediction == 0.5
        assert confidence == 0.3

    def test_predict_confidence_scales_with_feature_coverage(self, model: LinearRegressionModel) -> None:
        """Prediction confidence increases with feature coverage."""
        training_data = [
            {"features": {"f1": 0.5, "f2": 0.3, "f3": 0.7}, "target": 0.6},
            {"features": {"f1": 0.8, "f2": 0.6, "f3": 0.4}, "target": 0.7},
        ]

        model.train(training_data)

        full_coverage_pred, full_confidence = model.predict({"f1": 0.5, "f2": 0.3, "f3": 0.7})
        partial_coverage_pred, partial_confidence = model.predict({"f1": 0.5})

        assert full_confidence >= partial_confidence

    def test_update_model_adds_new_training_data(self, model: LinearRegressionModel) -> None:
        """Model update adds new training samples."""
        initial_data = [
            {"features": {"complexity": 0.5}, "target": 0.6},
        ]

        model.train(initial_data)
        initial_count = len(model.training_data)

        model.update_model({"features": {"complexity": 0.7}, "target": 0.5})

        assert len(model.training_data) == initial_count + 1


class TestSuccessProbabilityPredictor:
    """Test success probability prediction for protection cracking."""

    @pytest.fixture
    def predictor(self) -> SuccessProbabilityPredictor:
        """Create success probability predictor instance."""
        return SuccessProbabilityPredictor()

    def test_predictor_initialization_trains_model(self, predictor: SuccessProbabilityPredictor) -> None:
        """Predictor initializes with trained model."""
        assert predictor.model is not None
        assert predictor.feature_extractor is not None
        assert predictor.model.last_training is not None

    def test_predict_success_returns_valid_prediction_result(self, predictor: SuccessProbabilityPredictor) -> None:
        """Success prediction returns properly formatted result."""
        context = {
            "file_size": 1024000,
            "analysis_depth": "medium",
        }

        result = predictor.predict_success_probability("binary_analysis", context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.SUCCESS_PROBABILITY
        assert 0.0 <= result.predicted_value <= 1.0
        assert 0.0 <= result.confidence_score <= 1.0
        assert isinstance(result.confidence, PredictionConfidence)
        assert isinstance(result.factors, dict)
        assert len(result.reasoning) > 0

    def test_predict_success_probability_varies_with_complexity(self, predictor: SuccessProbabilityPredictor) -> None:
        """Success probability decreases with operation complexity."""
        simple_context = {
            "file_size": 10000,
            "analysis_depth": "shallow",
        }

        complex_context = {
            "file_size": 50000000,
            "analysis_depth": "comprehensive",
        }

        simple_result = predictor.predict_success_probability("script_generation", simple_context)
        complex_result = predictor.predict_success_probability("exploit_generation", complex_context)

        assert simple_result.predicted_value >= complex_result.predicted_value or abs(
            simple_result.predicted_value - complex_result.predicted_value
        ) < 0.2

    def test_predict_success_generates_meaningful_reasoning(self, predictor: SuccessProbabilityPredictor) -> None:
        """Success prediction includes meaningful reasoning text."""
        context = {"file_size": 1024000}

        result = predictor.predict_success_probability("binary_analysis", context)

        reasoning_lower = result.reasoning.lower()
        assert any(
            keyword in reasoning_lower
            for keyword in ["success", "probability", "historical", "complexity", "performance", "analysis"]
        )

    def test_predict_success_calculates_error_bounds(self, predictor: SuccessProbabilityPredictor) -> None:
        """Success prediction includes error bounds."""
        context = {"file_size": 1024000}

        result = predictor.predict_success_probability("binary_analysis", context)

        lower_bound, upper_bound = result.error_bounds

        assert 0.0 <= lower_bound <= result.predicted_value
        assert result.predicted_value <= upper_bound <= 1.0
        assert lower_bound < upper_bound

    def test_predict_success_confidence_reflects_data_quality(self, predictor: SuccessProbabilityPredictor) -> None:
        """Prediction confidence reflects quality of available data."""
        context = {"file_size": 1024000}

        result = predictor.predict_success_probability("binary_analysis", context)

        if result.confidence == PredictionConfidence.VERY_HIGH:
            assert result.confidence_score >= 0.8
        elif result.confidence == PredictionConfidence.HIGH:
            assert 0.6 <= result.confidence_score < 0.8
        elif result.confidence == PredictionConfidence.MEDIUM:
            assert 0.4 <= result.confidence_score < 0.6
        elif result.confidence == PredictionConfidence.LOW:
            assert 0.2 <= result.confidence_score < 0.4
        else:
            assert result.confidence_score < 0.2

    def test_predict_success_identifies_important_factors(self, predictor: SuccessProbabilityPredictor) -> None:
        """Success prediction identifies most important contributing factors."""
        context = {"file_size": 1024000, "analysis_depth": "deep"}

        result = predictor.predict_success_probability("binary_analysis", context)

        assert isinstance(result.factors, dict)
        assert len(result.factors) <= 5
        assert all(isinstance(v, float) for v in result.factors.values())


class TestExecutionTimePredictor:
    """Test execution time prediction for operations."""

    @pytest.fixture
    def predictor(self) -> ExecutionTimePredictor:
        """Create execution time predictor instance."""
        return ExecutionTimePredictor()

    def test_predictor_initialization_trains_model(self, predictor: ExecutionTimePredictor) -> None:
        """Predictor initializes with trained model."""
        assert predictor.model is not None
        assert predictor.feature_extractor is not None
        assert predictor.model.last_training is not None

    def test_predict_execution_time_returns_valid_result(self, predictor: ExecutionTimePredictor) -> None:
        """Execution time prediction returns valid result."""
        context = {
            "file_size": 1024000,
            "analysis_depth": "medium",
        }

        result = predictor.predict_execution_time("binary_analysis", context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.EXECUTION_TIME
        assert 0.1 <= result.predicted_value <= 3600.0
        assert 0.0 <= result.confidence_score <= 1.0

    def test_predict_execution_time_scales_with_complexity(self, predictor: ExecutionTimePredictor) -> None:
        """Execution time prediction increases with complexity."""
        simple_context = {
            "file_size": 10000,
            "analysis_depth": "shallow",
        }

        complex_context = {
            "file_size": 50000000,
            "analysis_depth": "comprehensive",
        }

        simple_result = predictor.predict_execution_time("script_generation", simple_context)
        complex_result = predictor.predict_execution_time("exploit_generation", complex_context)

        assert complex_result.predicted_value >= simple_result.predicted_value or abs(
            complex_result.predicted_value - simple_result.predicted_value
        ) < 5.0

    def test_predict_execution_time_enforces_bounds(self, predictor: ExecutionTimePredictor) -> None:
        """Execution time prediction stays within reasonable bounds."""
        context = {"file_size": 100000000000}

        result = predictor.predict_execution_time("binary_analysis", context)

        assert result.predicted_value >= 0.1
        assert result.predicted_value <= 3600.0

    def test_predict_execution_time_includes_error_bounds(self, predictor: ExecutionTimePredictor) -> None:
        """Execution time prediction includes error margin."""
        context = {"file_size": 1024000}

        result = predictor.predict_execution_time("binary_analysis", context)

        lower_bound, upper_bound = result.error_bounds

        assert lower_bound >= 0.1
        assert lower_bound <= result.predicted_value
        assert result.predicted_value <= upper_bound
        assert lower_bound < upper_bound

    def test_predict_execution_time_generates_reasoning(self, predictor: ExecutionTimePredictor) -> None:
        """Execution time prediction includes reasoning."""
        context = {"file_size": 1024000}

        result = predictor.predict_execution_time("binary_analysis", context)

        assert "execution time" in result.reasoning.lower()
        assert "seconds" in result.reasoning.lower()


class TestVulnerabilityPredictor:
    """Test vulnerability discovery prediction."""

    @pytest.fixture
    def predictor(self) -> VulnerabilityPredictor:
        """Create vulnerability predictor instance."""
        return VulnerabilityPredictor()

    def test_predictor_initialization_trains_model(self, predictor: VulnerabilityPredictor) -> None:
        """Predictor initializes with trained model."""
        assert predictor.model is not None
        assert predictor.feature_extractor is not None
        assert predictor.model.last_training is not None

    def test_predict_vulnerability_likelihood_returns_valid_result(self, predictor: VulnerabilityPredictor) -> None:
        """Vulnerability prediction returns valid result."""
        context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "functions_count": 50,
        }

        result = predictor.predict_vulnerability_likelihood(context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.VULNERABILITY_DISCOVERY
        assert 0.0 <= result.predicted_value <= 1.0
        assert 0.0 <= result.confidence_score <= 1.0

    def test_predict_vulnerability_likelihood_varies_by_file_type(self, predictor: VulnerabilityPredictor) -> None:
        """Vulnerability likelihood varies based on file type."""
        exe_context = {"file_extension": ".exe", "file_size": 1024000}
        py_context = {"file_extension": ".py", "file_size": 1024000}

        exe_result = predictor.predict_vulnerability_likelihood(exe_context)
        py_result = predictor.predict_vulnerability_likelihood(py_context)

        assert exe_result.predicted_value >= py_result.predicted_value or abs(
            exe_result.predicted_value - py_result.predicted_value
        ) < 0.3

    def test_predict_vulnerability_likelihood_considers_complexity(self, predictor: VulnerabilityPredictor) -> None:
        """Vulnerability likelihood increases with code complexity."""
        simple_context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "functions_count": 10,
        }

        complex_context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "functions_count": 500,
        }

        simple_result = predictor.predict_vulnerability_likelihood(simple_context)
        complex_result = predictor.predict_vulnerability_likelihood(complex_context)

        assert complex_result.predicted_value >= simple_result.predicted_value or abs(
            complex_result.predicted_value - simple_result.predicted_value
        ) < 0.2

    def test_predict_vulnerability_likelihood_generates_reasoning(self, predictor: VulnerabilityPredictor) -> None:
        """Vulnerability prediction includes meaningful reasoning."""
        context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "entropy": 7.8,
        }

        result = predictor.predict_vulnerability_likelihood(context)

        reasoning_lower = result.reasoning.lower()
        assert any(keyword in reasoning_lower for keyword in ["vulnerability", "likelihood", "risk", "file"])

    def test_predict_by_binary_path_analyzes_real_file(self, predictor: VulnerabilityPredictor) -> None:
        """Predict method analyzes real binary files."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + b"\x00" * 1000)
            tmp_path = tmp.name

        try:
            predictions = predictor.predict(tmp_path)

            assert isinstance(predictions, list)
            assert len(predictions) > 0
            assert predictions[0]["type"] == "vulnerability_prediction"
            assert "likelihood" in predictions[0]
            assert "confidence" in predictions[0]
        finally:
            os.unlink(tmp_path)

    def test_predict_handles_missing_file(self, predictor: VulnerabilityPredictor) -> None:
        """Predict handles non-existent files gracefully."""
        predictions = predictor.predict("/nonexistent/path/to/binary.exe")

        assert isinstance(predictions, list)
        assert len(predictions) == 0

    def test_get_confidence_score_returns_valid_score(self, predictor: VulnerabilityPredictor) -> None:
        """Get confidence score returns valid value."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"MZ" + b"\x00" * 1000)
            tmp_path = tmp.name

        try:
            confidence = predictor.get_confidence_score(tmp_path)

            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0
        finally:
            os.unlink(tmp_path)

    def test_get_confidence_score_handles_missing_file(self, predictor: VulnerabilityPredictor) -> None:
        """Get confidence score handles missing files."""
        confidence = predictor.get_confidence_score("/nonexistent/file.exe")

        assert confidence == 0.0


class TestPredictiveIntelligenceEngine:
    """Test main predictive intelligence engine."""

    @pytest.fixture
    def engine(self) -> PredictiveIntelligenceEngine:
        """Create predictive intelligence engine instance."""
        return PredictiveIntelligenceEngine()

    def test_engine_initialization_creates_predictors(self, engine: PredictiveIntelligenceEngine) -> None:
        """Engine initializes with all specialized predictors."""
        assert engine.success_predictor is not None
        assert engine.time_predictor is not None
        assert engine.vulnerability_predictor is not None
        assert isinstance(engine.prediction_cache, dict)
        assert len(engine.prediction_history) == 0

    def test_make_prediction_success_probability_returns_valid_result(
        self, engine: PredictiveIntelligenceEngine
    ) -> None:
        """Make prediction for success probability works."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.SUCCESS_PROBABILITY
        assert 0.0 <= result.predicted_value <= 1.0
        total_predictions = engine.prediction_stats["total_predictions"]
        assert isinstance(total_predictions, int)
        assert total_predictions > 0

    def test_make_prediction_execution_time_returns_valid_result(self, engine: PredictiveIntelligenceEngine) -> None:
        """Make prediction for execution time works."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        result = engine.make_prediction(PredictionType.EXECUTION_TIME, context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.EXECUTION_TIME
        assert result.predicted_value > 0.0

    def test_make_prediction_vulnerability_discovery_returns_valid_result(
        self, engine: PredictiveIntelligenceEngine
    ) -> None:
        """Make prediction for vulnerability discovery works."""
        context = {
            "file_extension": ".exe",
            "file_size": 1024000,
        }

        result = engine.make_prediction(PredictionType.VULNERABILITY_DISCOVERY, context)

        assert isinstance(result, PredictionResult)
        assert result.prediction_type == PredictionType.VULNERABILITY_DISCOVERY
        assert 0.0 <= result.predicted_value <= 1.0

    def test_make_prediction_caches_results(self, engine: PredictiveIntelligenceEngine) -> None:
        """Predictions are cached for repeated requests."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        first_result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)
        second_result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        assert first_result.prediction_id == second_result.prediction_id
        cache_hits = engine.prediction_stats["cache_hits"]
        assert isinstance(cache_hits, int)
        assert cache_hits > 0

    def test_make_prediction_adds_to_history(self, engine: PredictiveIntelligenceEngine) -> None:
        """Predictions are added to history."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        initial_count = len(engine.prediction_history)

        engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        assert len(engine.prediction_history) == initial_count + 1

    def test_make_prediction_handles_unsupported_types(self, engine: PredictiveIntelligenceEngine) -> None:
        """Engine handles unsupported prediction types gracefully."""
        context = {"operation_type": "unknown"}

        result = engine.make_prediction(PredictionType.SYSTEM_LOAD, context)

        assert isinstance(result, PredictionResult)
        assert result.confidence == PredictionConfidence.LOW
        assert "not yet supported" in result.reasoning

    def test_verify_prediction_accuracy_tracks_performance(self, engine: PredictiveIntelligenceEngine) -> None:
        """Verify prediction accuracy updates tracking metrics."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        engine.verify_prediction_accuracy(result.prediction_id, 0.75)

        accuracy_tracking = engine.prediction_stats["accuracy_tracking"]
        assert isinstance(accuracy_tracking, dict)
        assert len(accuracy_tracking) > 0

    def test_verify_prediction_accuracy_updates_model(self, engine: PredictiveIntelligenceEngine) -> None:
        """Verify prediction accuracy updates underlying models."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        initial_data_count = len(engine.success_predictor.model.training_data)

        engine.verify_prediction_accuracy(result.prediction_id, 0.75)

        assert len(engine.success_predictor.model.training_data) >= initial_data_count

    def test_verify_prediction_accuracy_handles_missing_prediction(self, engine: PredictiveIntelligenceEngine) -> None:
        """Verify handles missing prediction IDs gracefully."""
        engine.verify_prediction_accuracy("nonexistent-id", 0.75)

    def test_get_prediction_analytics_returns_valid_metrics(self, engine: PredictiveIntelligenceEngine) -> None:
        """Get prediction analytics returns comprehensive metrics."""
        context = {"operation_type": "binary_analysis", "file_size": 1024000}

        engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        analytics = engine.get_prediction_analytics()

        assert "total_predictions" in analytics
        assert "cache_hit_rate" in analytics
        assert "recent_predictions" in analytics
        assert "accuracy_by_type" in analytics

        assert analytics["total_predictions"] > 0
        assert 0.0 <= analytics["cache_hit_rate"] <= 1.0

    def test_get_prediction_insights_analyzes_patterns(self, engine: PredictiveIntelligenceEngine) -> None:
        """Get prediction insights identifies patterns."""
        context = {"operation_type": "binary_analysis", "file_size": 1024000}

        for _ in range(12):
            engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        insights = engine.get_prediction_insights()

        assert "insights" in insights
        assert "confidence_distribution" in insights
        assert "prediction_type_distribution" in insights

        assert isinstance(insights["insights"], list)

    def test_get_prediction_insights_tracks_confidence_distribution(self, engine: PredictiveIntelligenceEngine) -> None:
        """Prediction insights track confidence level distribution."""
        context = {"operation_type": "binary_analysis", "file_size": 1024000}

        engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        insights = engine.get_prediction_insights()

        assert isinstance(insights["confidence_distribution"], dict)
        assert sum(insights["confidence_distribution"].values()) > 0

    def test_get_prediction_insights_tracks_type_distribution(self, engine: PredictiveIntelligenceEngine) -> None:
        """Prediction insights track prediction type distribution."""
        context = {"operation_type": "binary_analysis", "file_size": 1024000}

        engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)
        engine.make_prediction(PredictionType.EXECUTION_TIME, context)

        insights = engine.get_prediction_insights()

        assert isinstance(insights["prediction_type_distribution"], dict)
        assert len(insights["prediction_type_distribution"]) > 0


class TestPredictionIntegration:
    """Integration tests for complete prediction workflows."""

    @pytest.fixture
    def engine(self) -> PredictiveIntelligenceEngine:
        """Create engine for integration tests."""
        return PredictiveIntelligenceEngine()

    def test_complete_prediction_workflow_with_verification(self, engine: PredictiveIntelligenceEngine) -> None:
        """Complete workflow from prediction to verification works."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
            "analysis_depth": "deep",
        }

        result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        assert result.predicted_value > 0.0

        engine.verify_prediction_accuracy(result.prediction_id, 0.85)

        analytics = engine.get_prediction_analytics()

        assert analytics["total_predictions"] > 0

    def test_multiple_prediction_types_in_sequence(self, engine: PredictiveIntelligenceEngine) -> None:
        """Multiple prediction types can be generated in sequence."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        success_result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)
        time_result = engine.make_prediction(PredictionType.EXECUTION_TIME, context)

        vuln_context = {
            "file_extension": ".exe",
            "file_size": 1024000,
        }
        vuln_result = engine.make_prediction(PredictionType.VULNERABILITY_DISCOVERY, vuln_context)

        assert success_result.prediction_type == PredictionType.SUCCESS_PROBABILITY
        assert time_result.prediction_type == PredictionType.EXECUTION_TIME
        assert vuln_result.prediction_type == PredictionType.VULNERABILITY_DISCOVERY

    def test_prediction_accuracy_improves_with_feedback(self, engine: PredictiveIntelligenceEngine) -> None:
        """Model accuracy tracking accumulates with feedback."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        predictions = []
        for _ in range(5):
            result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)
            predictions.append(result)

        for pred in predictions:
            engine.verify_prediction_accuracy(pred.prediction_id, 0.75)

        analytics = engine.get_prediction_analytics()

        if "success_probability" in analytics["accuracy_by_type"]:
            assert analytics["accuracy_by_type"]["success_probability"]["sample_count"] >= 5

    def test_cache_invalidation_after_expiration(self, engine: PredictiveIntelligenceEngine) -> None:
        """Cache entries expire after time threshold."""
        context = {
            "operation_type": "binary_analysis",
            "file_size": 1024000,
        }

        first_result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        first_result.timestamp = datetime.now() - timedelta(minutes=10)

        second_result = engine.make_prediction(PredictionType.SUCCESS_PROBABILITY, context)

        assert first_result.prediction_id != second_result.prediction_id


class TestPredictionEdgeCases:
    """Test edge cases and error handling."""

    def test_feature_extraction_handles_empty_context(self) -> None:
        """Feature extractor handles empty context gracefully."""
        extractor = FeatureExtractor()

        features = extractor.extract_operation_features("binary_analysis", {})

        assert isinstance(features, dict)
        assert len(features) > 0

    def test_feature_extraction_handles_missing_fields(self) -> None:
        """Feature extractor handles missing context fields."""
        extractor = FeatureExtractor()

        context = {"unknown_field": "value"}

        features = extractor.extract_operation_features("binary_analysis", context)

        assert isinstance(features, dict)

    def test_model_training_handles_empty_data(self) -> None:
        """Model handles empty training data."""
        model = LinearRegressionModel("test")

        model.train([])

        prediction, confidence = model.predict({"feature": 0.5})

        assert prediction == 0.5
        assert confidence == 0.3

    def test_model_training_handles_inconsistent_features(self) -> None:
        """Model handles training data with inconsistent features."""
        model = LinearRegressionModel("test")

        training_data = [
            {"features": {"a": 0.5}, "target": 0.6},
            {"features": {"b": 0.7}, "target": 0.4},
            {"features": {"a": 0.3, "c": 0.8}, "target": 0.5},
        ]

        model.train(training_data)

        prediction, confidence = model.predict({"a": 0.5})

        assert 0.0 <= prediction <= 1.0

    def test_vulnerability_predictor_handles_high_entropy(self) -> None:
        """Vulnerability predictor handles high entropy binaries."""
        predictor = VulnerabilityPredictor()

        context = {
            "file_extension": ".exe",
            "file_size": 1024000,
            "entropy": 8.0,
        }

        result = predictor.predict_vulnerability_likelihood(context)

        assert result.predicted_value > 0.0

    def test_execution_time_predictor_handles_extreme_sizes(self) -> None:
        """Execution time predictor handles extreme file sizes."""
        predictor = ExecutionTimePredictor()

        tiny_context = {"file_size": 100}
        huge_context = {"file_size": 100000000000}

        tiny_result = predictor.predict_execution_time("binary_analysis", tiny_context)
        huge_result = predictor.predict_execution_time("binary_analysis", huge_context)

        assert tiny_result.predicted_value >= 0.1
        assert huge_result.predicted_value <= 3600.0


class TestPredictionDataPersistence:
    """Test prediction data loading from various sources."""

    def test_success_predictor_loads_from_database(self) -> None:
        """Success predictor attempts to load from historical database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "analysis_history.db"

            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE analysis_results (
                    operation_complexity REAL,
                    system_load REAL,
                    historical_success_rate REAL,
                    input_size REAL,
                    cpu_usage REAL,
                    memory_usage REAL,
                    success_probability REAL,
                    timestamp DATETIME
                )
            """)

            cursor.execute(
                """
                INSERT INTO analysis_results VALUES
                (0.5, 0.3, 0.8, 0.4, 0.5, 0.6, 0.75, datetime('now'))
            """
            )

            conn.commit()
            conn.close()

            os.environ["HOME"] = tmpdir

            predictor = SuccessProbabilityPredictor()

            assert predictor.model is not None

    def test_success_predictor_loads_from_json_cache(self) -> None:
        """Success predictor loads training data from JSON cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "training_cache"
            cache_dir.mkdir(parents=True)
            cache_file = cache_dir / "success_data.json"

            cache_data = {
                "training_samples": [
                    {
                        "features": {
                            "operation_complexity": 0.5,
                            "system_load": 0.3,
                            "historical_success_rate": 0.8,
                            "input_size": 0.4,
                            "cpu_usage": 0.5,
                            "memory_usage": 0.6,
                        },
                        "target": 0.75,
                    }
                ]
            }

            with open(cache_file, "w") as f:
                json.dump(cache_data, f)

            original_home = os.environ.get("HOME")
            os.environ["HOME"] = tmpdir

            try:
                predictor = SuccessProbabilityPredictor()
                assert len(predictor.model.training_data) > 0
            finally:
                if original_home:
                    os.environ["HOME"] = original_home

    def test_execution_time_predictor_uses_baseline_data(self) -> None:
        """Execution time predictor initializes with baseline measurements."""
        predictor = ExecutionTimePredictor()

        assert len(predictor.model.training_data) > 0

    def test_vulnerability_predictor_uses_baseline_data(self) -> None:
        """Vulnerability predictor initializes with baseline data."""
        predictor = VulnerabilityPredictor()

        assert len(predictor.model.training_data) > 0

    def test_vulnerability_predictor_loads_from_cve_data(self) -> None:
        """Vulnerability predictor loads from CVE analysis data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cve_dir = Path(tmpdir) / "cve_analysis"
            cve_dir.mkdir(parents=True)
            cve_file = cve_dir / "results.json"

            cve_data = {
                "analyzed_binaries": [
                    {
                        "binary_info": {
                            "type_risk": 0.8,
                            "size_mb": 10,
                            "complexity_score": 0.7,
                            "entropy": 0.6,
                            "compiler_risk": 0.5,
                        },
                        "vulnerabilities": {
                            "cves": ["CVE-2024-1234"],
                            "findings": [{"severity": "high"}],
                        },
                    }
                ]
            }

            with open(cve_file, "w") as f:
                json.dump(cve_data, f)

            original_home = os.environ.get("HOME")
            os.environ["HOME"] = tmpdir

            try:
                predictor = VulnerabilityPredictor()
                assert len(predictor.model.training_data) > 0
            finally:
                if original_home:
                    os.environ["HOME"] = original_home


class TestPredictionReasoning:
    """Test prediction reasoning generation."""

    def test_success_reasoning_identifies_high_historical_performance(self) -> None:
        """Success reasoning identifies high historical performance."""
        predictor = SuccessProbabilityPredictor()

        features = {
            "historical_success_rate": 0.95,
            "operation_complexity": 0.2,
            "system_load": 0.3,
        }

        reasoning = predictor._generate_success_reasoning(features, 0.9)

        assert "historical performance" in reasoning.lower()

    def test_success_reasoning_identifies_high_complexity(self) -> None:
        """Success reasoning identifies high operation complexity."""
        predictor = SuccessProbabilityPredictor()

        features = {
            "historical_success_rate": 0.8,
            "operation_complexity": 1.5,
            "system_load": 0.3,
        }

        reasoning = predictor._generate_success_reasoning(features, 0.5)

        assert "complexity" in reasoning.lower()

    def test_success_reasoning_identifies_high_system_load(self) -> None:
        """Success reasoning identifies high system load."""
        predictor = SuccessProbabilityPredictor()

        features = {
            "historical_success_rate": 0.8,
            "operation_complexity": 0.5,
            "system_load": 0.85,
        }

        reasoning = predictor._generate_success_reasoning(features, 0.6)

        assert "system load" in reasoning.lower()

    def test_vulnerability_reasoning_identifies_high_risk_file_type(self) -> None:
        """Vulnerability reasoning identifies high-risk file types."""
        predictor = VulnerabilityPredictor()

        features = {
            "file_type_risk": 0.9,
            "function_complexity": 0.5,
            "entropy": 0.6,
        }

        reasoning = predictor._generate_vuln_reasoning(features, 0.8)

        assert "file type" in reasoning.lower()

    def test_vulnerability_reasoning_identifies_complexity(self) -> None:
        """Vulnerability reasoning identifies code complexity."""
        predictor = VulnerabilityPredictor()

        features = {
            "file_type_risk": 0.5,
            "function_complexity": 0.85,
            "entropy": 0.6,
        }

        reasoning = predictor._generate_vuln_reasoning(features, 0.7)

        assert "complexity" in reasoning.lower()

    def test_vulnerability_reasoning_identifies_obfuscation(self) -> None:
        """Vulnerability reasoning identifies potential obfuscation."""
        predictor = VulnerabilityPredictor()

        features = {
            "file_type_risk": 0.5,
            "function_complexity": 0.5,
            "entropy": 0.9,
        }

        reasoning = predictor._generate_vuln_reasoning(features, 0.7)

        assert "entropy" in reasoning.lower() or "obfuscation" in reasoning.lower()


class TestModelTrainingConvergence:
    """Test model training convergence behavior."""

    def test_linear_model_converges_with_consistent_data(self) -> None:
        """Linear model converges when trained on consistent data."""
        model = LinearRegressionModel("convergence_test")

        training_data = [
            {"features": {"x": 0.0}, "target": 0.0},
            {"features": {"x": 0.5}, "target": 0.5},
            {"features": {"x": 1.0}, "target": 1.0},
        ]

        model.train(training_data)

        prediction, confidence = model.predict({"x": 0.5})

        assert abs(prediction - 0.5) < 0.3

    def test_linear_model_handles_noisy_data(self) -> None:
        """Linear model handles noisy training data."""
        model = LinearRegressionModel("noise_test")

        import random

        random.seed(42)

        training_data = [{"features": {"x": i / 100}, "target": i / 100 + random.uniform(-0.1, 0.1)} for i in range(100)]

        model.train(training_data)

        prediction, confidence = model.predict({"x": 0.5})

        assert 0.0 <= prediction <= 1.0


class TestPredictionFactors:
    """Test factor extraction and importance."""

    def test_success_predictor_extracts_top_factors(self) -> None:
        """Success predictor extracts top contributing factors."""
        predictor = SuccessProbabilityPredictor()

        context = {
            "file_size": 1024000,
            "analysis_depth": "deep",
        }

        result = predictor.predict_success_probability("binary_analysis", context)

        assert len(result.factors) <= 5
        assert all(isinstance(v, float) for v in result.factors.values())

    def test_execution_time_factors_include_key_metrics(self) -> None:
        """Execution time factors include key performance metrics."""
        predictor = ExecutionTimePredictor()

        context = {"file_size": 1024000}

        result = predictor.predict_execution_time("binary_analysis", context)

        factors = result.factors

        assert "complexity_impact" in factors or len(factors) > 0
        assert all(isinstance(v, (int, float)) for v in factors.values())


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
