"""Predictive Analysis & Intelligence Engine.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import math
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from intellicrack.logger import logger

from ..utils.logger import get_logger
from .learning_engine_simple import get_learning_engine
from .performance_monitor import profile_ai_operation

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in predictive_intelligence: %s", e)
    np = None
    NUMPY_AVAILABLE = False

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in predictive_intelligence: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


logger = get_logger(__name__)


class PredictionType(Enum):
    """Types of predictions the system can make."""

    SUCCESS_PROBABILITY = "success_probability"
    EXECUTION_TIME = "execution_time"
    RESOURCE_USAGE = "resource_usage"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOIT_SUCCESS = "exploit_success"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    ERROR_LIKELIHOOD = "error_likelihood"
    OPTIMAL_STRATEGY = "optimal_strategy"
    LEARNING_CONVERGENCE = "learning_convergence"
    SYSTEM_LOAD = "system_load"


class PredictionConfidence(Enum):
    """Confidence levels for predictions."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class PredictionInput:
    """Input data for making predictions."""

    operation_type: str
    context: dict[str, Any]
    historical_data: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PredictionResult:
    """Result of a prediction."""

    prediction_id: str
    prediction_type: PredictionType
    predicted_value: float
    confidence: PredictionConfidence
    confidence_score: float  # 0.0 to 1.0
    factors: dict[str, float]  # Contributing factors
    reasoning: str
    timestamp: datetime = field(default_factory=datetime.now)
    model_version: str = "1.0"
    error_bounds: tuple[float, float] = (0.0, 0.0)


@dataclass
class TimeSeriesData:
    """Time series data for predictions."""

    timestamps: list[datetime]
    values: list[float]
    metadata: list[dict[str, Any]] = field(default_factory=list)


class FeatureExtractor:
    """Extracts features for predictive modeling."""

    def __init__(self):
        """Initialize the feature extractor for predictive modeling.

        Sets up feature caching, importance tracking, and connects to the learning engine
        for intelligent feature extraction from binary analysis data.
        """
        self.logger = logging.getLogger(__name__ + ".FeatureExtractor")
        self.feature_cache: dict[str, Any] = {}
        self.feature_importance: dict[str, float] = {}
        self.learning_engine = get_learning_engine()

        logger.info("Feature extractor initialized")

    def extract_operation_features(
        self, operation_type: str, context: dict[str, Any]
    ) -> dict[str, float]:
        """Extract features for operation prediction."""
        features = {}

        # Basic operation features
        features["operation_complexity"] = self._calculate_operation_complexity(
            operation_type, context
        )
        features["input_size"] = self._calculate_input_size(context)
        features["context_richness"] = len(context)

        # Historical performance features
        historical_performance = self._get_historical_performance(operation_type)
        features.update(historical_performance)

        # System state features
        system_features = self._extract_system_features()
        features.update(system_features)

        # Time-based features
        time_features = self._extract_time_features()
        features.update(time_features)

        return features

    def _calculate_operation_complexity(
        self, operation_type: str, context: dict[str, Any]
    ) -> float:
        """Calculate complexity score for operation."""
        complexity_map = {
            "binary_analysis": 0.7,
            "vulnerability_analysis": 0.8,
            "exploit_generation": 0.9,
            "code_modification": 0.6,
            "semantic_analysis": 0.7,
            "script_generation": 0.5,
        }

        base_complexity = complexity_map.get(operation_type, 0.5)

        # Adjust based on context
        if "file_size" in context:
            size_factor = min(context["file_size"] / 1000000, 2.0)  # Normalize to MB
            base_complexity += size_factor * 0.2

        if "analysis_depth" in context:
            depth_map = {"shallow": 0.0, "medium": 0.2, "deep": 0.4, "comprehensive": 0.6}
            base_complexity += depth_map.get(context["analysis_depth"], 0.2)

        return min(base_complexity, 2.0)

    def _calculate_input_size(self, context: dict[str, Any]) -> float:
        """Calculate normalized input size."""
        size_indicators = ["file_size", "data_size", "input_length", "code_lines"]

        for indicator in size_indicators:
            if indicator in context:
                # Normalize to a 0-1 scale with log scaling for large values
                raw_size = context[indicator]
                if raw_size > 0:
                    # log10(1M) ≈ 6
                    return min(math.log10(raw_size + 1) / 6.0, 1.0)

        return 0.1  # Default small size

    def _get_historical_performance(self, operation_type: str) -> dict[str, float]:
        """Get historical performance features."""
        try:
            insights = self.learning_engine.get_learning_insights()

            # Use operation_type to filter relevant insights
            if operation_type in insights.get("operation_types", {}):
                type_specific_insights = insights["operation_types"][operation_type]
                logger.debug(f"Found type-specific insights for {operation_type}")
            else:
                type_specific_insights = {}
                logger.debug(f"No specific insights for operation type: {operation_type}")

            features = {
                "historical_success_rate": type_specific_insights.get(
                    "success_rate", insights.get("success_rate", 0.8)
                ),
                "avg_execution_time": type_specific_insights.get(
                    "avg_execution_time", insights.get("avg_execution_time", 5.0)
                ),
                "historical_confidence": type_specific_insights.get(
                    "avg_confidence", insights.get("avg_confidence", 0.7)
                ),
            }

            # Normalize execution time
            features["normalized_exec_time"] = min(features["avg_execution_time"] / 60.0, 1.0)

            return features

        except Exception as e:
            logger.error(f"Error getting historical performance: {e}")
            return {
                "historical_success_rate": 0.8,
                "avg_execution_time": 5.0,
                "historical_confidence": 0.7,
                "normalized_exec_time": 0.08,
            }

    def _extract_system_features(self) -> dict[str, float]:
        """Extract current system state features."""
        if not PSUTIL_AVAILABLE:
            return {
                "cpu_usage": 0.5,
                "memory_usage": 0.5,
                "system_load": 0.5,
                "disk_activity": 0.3,
            }

        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent() / 100.0
            memory_percent = psutil.virtual_memory().percent / 100.0

            # Load average (Unix-like systems)
            try:
                load_avg = psutil.getloadavg()[0] / psutil.cpu_count(logical=False)
            except (AttributeError, OSError) as e:
                self.logger.error("Error in predictive_intelligence: %s", e)
                load_avg = cpu_percent  # Fallback for Windows

            features = {
                "cpu_usage": cpu_percent,
                "memory_usage": memory_percent,
                "system_load": min(load_avg, 2.0),
            }

            # Disk I/O if available
            try:
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    features["disk_activity"] = min(
                        (disk_io.read_bytes + disk_io.write_bytes) / (1024**3),
                        1.0,
                    )
            except (AttributeError, OSError):
                features["disk_activity"] = 0.1

            return features

        except Exception as e:
            logger.error(f"Error extracting system features: {e}")
            return {
                "cpu_usage": 0.3,
                "memory_usage": 0.5,
                "system_load": 0.4,
                "disk_activity": 0.1,
            }

    def _extract_time_features(self) -> dict[str, float]:
        """Extract time-based features."""
        now = datetime.now()

        # Hour of day (0-23 normalized to 0-1)
        hour_normalized = now.hour / 23.0

        # Day of week (0-6 normalized to 0-1)
        weekday_normalized = now.weekday() / 6.0

        # Business hours indicator
        is_business_hours = 1.0 if 9 <= now.hour <= 17 and now.weekday() < 5 else 0.0

        return {
            "hour_of_day": hour_normalized,
            "day_of_week": weekday_normalized,
            "is_business_hours": is_business_hours,
        }

    def extract_vulnerability_features(
        self, vulnerability_context: dict[str, Any]
    ) -> dict[str, float]:
        """Extract features for vulnerability prediction."""
        features = {}

        # File type features
        file_extension = vulnerability_context.get("file_extension", "").lower()
        extension_risk = {
            ".exe": 0.9,
            ".dll": 0.8,
            ".sys": 0.95,
            ".bat": 0.7,
            ".ps1": 0.8,
            ".vbs": 0.7,
            ".js": 0.6,
            ".py": 0.5,
            ".c": 0.4,
            ".cpp": 0.4,
            ".java": 0.3,
        }
        features["file_type_risk"] = extension_risk.get(file_extension, 0.5)

        # Size-based features
        file_size = vulnerability_context.get("file_size", 0)
        features["size_risk"] = min(file_size / (10 * 1024 * 1024), 1.0)  # 10MB baseline

        # Complexity features
        functions_count = vulnerability_context.get("functions_count", 0)
        features["function_complexity"] = min(functions_count / 100.0, 1.0)

        # Compiler and platform features
        compiler = vulnerability_context.get("compiler", "unknown").lower()
        compiler_risk = {"gcc": 0.3, "msvc": 0.5, "clang": 0.3, "unknown": 0.7}
        features["compiler_risk"] = compiler_risk.get(compiler, 0.7)

        # Age and entropy features
        if "entropy" in vulnerability_context:
            features["entropy"] = min(vulnerability_context["entropy"] / 8.0, 1.0)  # Normalize

        return features

    def extract_exploit_features(self, exploit_context: dict[str, Any]) -> dict[str, float]:
        """Extract features for exploit success prediction."""
        features = {}

        # Vulnerability type features
        vuln_type = exploit_context.get("vulnerability_type", "unknown")
        type_success_rates = {
            "buffer_overflow": 0.8,
            "use_after_free": 0.6,
            "format_string": 0.7,
            "integer_overflow": 0.5,
            "code_injection": 0.9,
        }
        features["vuln_type_baseline"] = type_success_rates.get(vuln_type, 0.5)

        # Target system features
        target_os = exploit_context.get("target_os", "unknown").lower()
        os_difficulty = {"windows": 0.6, "linux": 0.7, "macos": 0.8, "unknown": 0.8}
        features["target_difficulty"] = os_difficulty.get(target_os, 0.8)

        # Protection features
        protections = exploit_context.get("protections", [])
        protection_penalty = len(protections) * 0.1
        features["protection_difficulty"] = min(protection_penalty, 0.8)

        # Exploit complexity
        chain_length = exploit_context.get("chain_length", 1)
        features["chain_complexity"] = min(chain_length / 5.0, 1.0)

        return features


class PredictiveModel:
    """Base class for predictive models."""

    def __init__(self, model_name: str):
        """Initialize the base predictive model.

        Args:
            model_name: Name identifier for the predictive model.

        """
        self.model_name = model_name
        self.model_version = "1.0"
        self.training_data: list[dict[str, Any]] = []
        self.model_parameters: dict[str, Any] = {}
        self.feature_importance: dict[str, float] = {}
        self.last_training: datetime | None = None

    def train(self, training_data: list[dict[str, Any]]):
        """Train the model with provided data."""
        self.training_data = training_data
        self.last_training = datetime.now()
        logger.info(f"Model {self.model_name} trained with {len(training_data)} samples")

    def predict(self, features: dict[str, float]) -> tuple[float, float]:
        """Make prediction. Returns (prediction, confidence)."""
        # Implementation should use features to make actual predictions
        if not features:
            return 0.0, 0.0

        # Basic fallback prediction based on feature analysis
        feature_count = len(features)
        avg_value = sum(features.values()) / feature_count if feature_count > 0 else 0.0
        # More features = higher confidence
        confidence = min(1.0, feature_count / 10.0)

        logger.debug(
            f"Fallback prediction using {feature_count} features: {avg_value:.3f} (confidence: {confidence:.3f})"
        )
        raise NotImplementedError(
            f"Subclasses must implement predict method. Fallback for {feature_count} features would return {avg_value:.3f}"
        )

    def update_model(self, new_data: dict[str, Any]):
        """Update model with new data point."""
        self.training_data.append(new_data)

        # Retrain if we have enough new data
        if len(self.training_data) % 100 == 0:
            self.train(self.training_data)


class LinearRegressionModel(PredictiveModel):
    """Simple linear regression model for predictions."""

    def __init__(self, model_name: str):
        """Initialize the linear regression model.

        Args:
            model_name: Name identifier for the model.

        """
        super().__init__(model_name)
        self.weights: dict[str, float] = {}
        self.bias: float = 0.0
        self.learning_rate = 0.01

    def train(self, training_data: list[dict[str, Any]]):
        """Train linear regression model."""
        super().train(training_data)

        if not training_data:
            return

        # Extract features and targets
        feature_names = set()
        for sample in training_data:
            if "features" in sample:
                feature_names.update(sample["features"].keys())

        feature_names = list(feature_names)

        # Initialize weights if needed
        if not self.weights:
            self.weights = dict.fromkeys(feature_names, 0.1)

        # Simple gradient descent training
        for epoch in range(50):  # Limited epochs for real-time training
            total_error = 0.0

            if epoch % 10 == 0:
                logger.debug(f"Training epoch {epoch}/50")

            for sample in training_data:
                features = sample.get("features", {})
                target = sample.get("target", 0.0)

                # Forward pass
                prediction = self.bias
                for feature_name, value in features.items():
                    if feature_name in self.weights:
                        prediction += self.weights[feature_name] * value

                # Calculate error
                error = target - prediction
                total_error += error**2

                # Backward pass (gradient descent)
                self.bias += self.learning_rate * error
                for feature_name, value in features.items():
                    if feature_name in self.weights:
                        self.weights[feature_name] += self.learning_rate * error * value

            # Early stopping if converged
            if total_error < 0.001:
                break

        # Calculate feature importance
        total_weight = sum(abs(w) for w in self.weights.values())
        if total_weight > 0:
            self.feature_importance = {
                name: abs(weight) / total_weight for name, weight in self.weights.items()
            }

        logger.info(f"Linear model {self.model_name} training completed")

    def predict(self, features: dict[str, float]) -> tuple[float, float]:
        """Make prediction using linear model."""
        if not self.weights:
            # No training data - return default prediction
            return 0.5, 0.3

        # Calculate prediction
        prediction = self.bias
        for feature_name, value in features.items():
            if feature_name in self.weights:
                prediction += self.weights[feature_name] * value

        # Calculate confidence based on feature coverage
        covered_features = sum(1 for name in features if name in self.weights)
        total_features = len(self.weights)
        coverage = covered_features / max(total_features, 1)

        # Base confidence on training data size and feature coverage
        base_confidence = min(len(self.training_data) / 100.0, 0.9)
        confidence = base_confidence * coverage

        return max(0.0, min(prediction, 1.0)), max(0.1, min(confidence, 1.0))


class SuccessProbabilityPredictor:
    """Predicts success probability for operations."""

    def __init__(self):
        """Initialize the success probability predictor.

        Sets up a linear regression model and feature extractor for predicting
        the likelihood of successful exploitation operations.
        """
        self.model = LinearRegressionModel("success_probability")
        self.feature_extractor = FeatureExtractor()
        self._initialize_model()

        logger.info("Success probability predictor initialized")

    def _initialize_model(self):
        """Initialize model with synthetic training data."""
        # Create synthetic training data based on typical patterns
        training_data = []

        for sample_idx in range(200):
            # Generate synthetic features with some variation based on index
            complexity_base = 0.2 + (sample_idx % 10) * 0.1  # Varies based on index

            if NUMPY_AVAILABLE:
                features = {
                    "operation_complexity": np.random.uniform(complexity_base, 1.5),
                    "system_load": np.random.uniform(0.1, 0.9),
                    "historical_success_rate": np.random.uniform(0.6, 0.95),
                    "input_size": np.random.uniform(0.1, 1.0),
                    "cpu_usage": np.random.uniform(0.2, 0.8),
                    "memory_usage": np.random.uniform(0.3, 0.9),
                }
            else:
                # Fallback random values when numpy is not available
                import random

                features = {
                    "operation_complexity": random.uniform(complexity_base, 1.5),  # noqa: S311
                    "system_load": random.uniform(0.1, 0.9),  # noqa: S311
                    "historical_success_rate": random.uniform(0.6, 0.95),  # noqa: S311
                    "input_size": random.uniform(0.1, 1.0),  # noqa: S311
                    "cpu_usage": random.uniform(0.2, 0.8),  # noqa: S311
                    "memory_usage": random.uniform(0.3, 0.9),  # noqa: S311
                }

            # Calculate synthetic target based on realistic relationships
            target = (
                0.8 * features["historical_success_rate"]
                + 0.1 * (1.0 - features["operation_complexity"])
                + 0.05 * (1.0 - features["system_load"])
                + 0.05 * (1.0 - features["cpu_usage"])
            )

            # Add some noise
            if NUMPY_AVAILABLE:
                target += np.random.normal(0, 0.1)
            else:
                import random

                target += random.gauss(0, 0.1)
            target = max(0.0, min(target, 1.0))

            training_data.append(
                {
                    "features": features,
                    "target": target,
                }
            )

        self.model.train(training_data)

    @profile_ai_operation("success_prediction")
    def predict_success_probability(
        self, operation_type: str, context: dict[str, Any]
    ) -> PredictionResult:
        """Predict success probability for operation."""
        # Extract features
        features = self.feature_extractor.extract_operation_features(operation_type, context)

        # Make prediction
        predicted_value, confidence_score = self.model.predict(features)

        # Determine confidence level
        if confidence_score >= 0.8:
            confidence = PredictionConfidence.VERY_HIGH
        elif confidence_score >= 0.6:
            confidence = PredictionConfidence.HIGH
        elif confidence_score >= 0.4:
            confidence = PredictionConfidence.MEDIUM
        elif confidence_score >= 0.2:
            confidence = PredictionConfidence.LOW
        else:
            confidence = PredictionConfidence.VERY_LOW

        # Generate reasoning
        reasoning = self._generate_success_reasoning(features, predicted_value)

        # Calculate error bounds
        error_margin = (1.0 - confidence_score) * 0.2
        error_bounds = (
            max(0.0, predicted_value - error_margin),
            min(1.0, predicted_value + error_margin),
        )

        return PredictionResult(
            prediction_id=str(uuid.uuid4()),
            prediction_type=PredictionType.SUCCESS_PROBABILITY,
            predicted_value=predicted_value,
            confidence=confidence,
            confidence_score=confidence_score,
            factors=self._get_important_factors(features),
            reasoning=reasoning,
            error_bounds=error_bounds,
        )

    def _generate_success_reasoning(
        self, features: dict[str, float], predicted_value: float
    ) -> str:
        """Generate reasoning for success prediction."""
        factors = []

        if features.get("historical_success_rate", 0.8) > 0.9:
            factors.append("strong historical performance")
        elif features.get("historical_success_rate", 0.8) < 0.7:
            factors.append("concerning historical performance")

        if features.get("operation_complexity", 0.5) > 1.0:
            factors.append("high operation complexity")
        elif features.get("operation_complexity", 0.5) < 0.3:
            factors.append("low operation complexity")

        if features.get("system_load", 0.5) > 0.8:
            factors.append("high system load")

        if predicted_value > 0.8:
            outcome = "high success probability"
        elif predicted_value > 0.6:
            outcome = "moderate success probability"
        else:
            outcome = "low success probability"

        if factors:
            return f"Predicted {outcome} based on {', '.join(factors)}"
        return f"Predicted {outcome} based on overall system analysis"

    def _get_important_factors(self, features: dict[str, float]) -> dict[str, float]:
        """Get most important contributing factors."""
        factor_weights = self.model.feature_importance

        if not factor_weights:
            # Default importance if no training
            factor_weights = {name: 1.0 / len(features) for name in features}

        # Return top contributing factors
        sorted_factors = sorted(
            factor_weights.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return dict(sorted_factors[:5])  # Top 5 factors


class ExecutionTimePredictor:
    """Predicts execution time for operations."""

    def __init__(self):
        """Initialize the execution time predictor.

        Sets up a linear regression model and feature extractor for predicting
        operation execution times based on binary characteristics.
        """
        self.model = LinearRegressionModel("execution_time")
        self.feature_extractor = FeatureExtractor()
        self._initialize_model()

        logger.info("Execution time predictor initialized")

    def _initialize_model(self):
        """Initialize model with synthetic training data."""
        training_data = []

        for time_sample_idx in range(150):
            # Vary complexity based on sample index for diversity
            complexity_factor = 0.2 + (time_sample_idx % 15) * 0.1

            if NUMPY_AVAILABLE:
                features = {
                    "operation_complexity": np.random.uniform(complexity_factor, 2.0),
                    "input_size": np.random.uniform(0.1, 1.0),
                    "system_load": np.random.uniform(0.1, 0.9),
                    "cpu_usage": np.random.uniform(0.2, 0.8),
                    "historical_success_rate": np.random.uniform(0.6, 0.95),
                }
            else:
                import random

                features = {
                    "operation_complexity": random.uniform(complexity_factor, 2.0),  # noqa: S311
                    "input_size": random.uniform(0.1, 1.0),  # noqa: S311
                    "system_load": random.uniform(0.1, 0.9),  # noqa: S311
                    "cpu_usage": random.uniform(0.2, 0.8),  # noqa: S311
                    "historical_success_rate": random.uniform(0.6, 0.95),  # noqa: S311
                }

            # Execution time correlates with complexity and system load
            base_time = (
                features["operation_complexity"] * 10.0
                + features["input_size"] * 5.0
                + features["system_load"] * 8.0
                + features["cpu_usage"] * 3.0
            )

            # Add noise and ensure positive
            if NUMPY_AVAILABLE:
                noise = np.random.normal(0, 2.0)
            else:
                import random

                noise = random.gauss(0, 2.0)
            target = max(0.5, base_time + noise)

            training_data.append(
                {
                    "features": features,
                    "target": target,
                }
            )

        self.model.train(training_data)

    @profile_ai_operation("time_prediction")
    def predict_execution_time(
        self, operation_type: str, context: dict[str, Any]
    ) -> PredictionResult:
        """Predict execution time for operation."""
        features = self.feature_extractor.extract_operation_features(operation_type, context)

        predicted_time, confidence_score = self.model.predict(features)

        # Ensure reasonable time bounds
        predicted_time = max(0.1, min(predicted_time, 3600.0))  # 1 hour max

        # Determine confidence level
        if confidence_score >= 0.8:
            confidence = PredictionConfidence.VERY_HIGH
        elif confidence_score >= 0.6:
            confidence = PredictionConfidence.HIGH
        elif confidence_score >= 0.4:
            confidence = PredictionConfidence.MEDIUM
        else:
            confidence = PredictionConfidence.LOW

        # Generate reasoning
        reasoning = f"Estimated execution time of {predicted_time:.1f} seconds based on operation complexity and system state"

        # Error bounds (±20% for time predictions)
        error_margin = predicted_time * 0.2 * (1.0 - confidence_score)
        error_bounds = (
            max(0.1, predicted_time - error_margin),
            predicted_time + error_margin,
        )

        return PredictionResult(
            prediction_id=str(uuid.uuid4()),
            prediction_type=PredictionType.EXECUTION_TIME,
            predicted_value=predicted_time,
            confidence=confidence,
            confidence_score=confidence_score,
            factors=self._get_time_factors(features),
            reasoning=reasoning,
            error_bounds=error_bounds,
        )

    def _get_time_factors(self, features: dict[str, float]) -> dict[str, float]:
        """Get factors affecting execution time."""
        return {
            "complexity_impact": features.get("operation_complexity", 0.5),
            "size_impact": features.get("input_size", 0.5),
            "system_load_impact": features.get("system_load", 0.5),
            "cpu_impact": features.get("cpu_usage", 0.5),
        }


class VulnerabilityPredictor:
    """Predicts vulnerability discovery likelihood."""

    def __init__(self):
        """Initialize the vulnerability discovery predictor.

        Sets up the predictor for estimating vulnerability discovery likelihood
        in target binaries based on code patterns and historical data.
        """
        self.model = LinearRegressionModel("vulnerability_discovery")
        self.feature_extractor = FeatureExtractor()
        self.vulnerability_patterns = []
        self.pattern_weights = {}
        self.discovery_history = []
        self._initialize_model()

        logger.info("Vulnerability predictor initialized")

    def _initialize_model(self):
        """Initialize with vulnerability-specific training data."""
        training_data = []

        for vuln_sample_idx in range(300):
            # File characteristics with variation based on sample index
            if NUMPY_AVAILABLE:
                file_type_risk = np.random.choice([0.3, 0.5, 0.7, 0.9], p=[0.3, 0.3, 0.3, 0.1])
                size_risk = np.random.uniform(0.1, 1.0)
                complexity = np.random.uniform(0.2, 1.0)
                entropy = np.random.uniform(0.3, 1.0)
            else:
                import random

                file_type_risk = random.choices(  # noqa: S311
                    [0.3, 0.5, 0.7, 0.9], weights=[0.3, 0.3, 0.3, 0.1]
                )[0]
                size_risk = random.uniform(0.1, 1.0)  # noqa: S311
                complexity = random.uniform(0.2, 1.0)  # noqa: S311
                entropy = random.uniform(0.3, 1.0)  # noqa: S311

            # Add some pattern based on index for model diversity
            if vuln_sample_idx % 20 == 0:
                entropy *= 1.2  # Increase entropy for every 20th sample

            if NUMPY_AVAILABLE:
                compiler_risk = np.random.uniform(0.2, 0.8)
            else:
                import random

                compiler_risk = random.uniform(0.2, 0.8)  # noqa: S311

            features = {
                "file_type_risk": file_type_risk,
                "size_risk": size_risk,
                "function_complexity": complexity,
                "entropy": entropy,
                "compiler_risk": compiler_risk,
            }

            # Vulnerability probability
            vuln_prob = (
                0.3 * file_type_risk
                + 0.2 * size_risk
                + 0.25 * complexity
                + 0.15 * entropy
                + 0.1 * features["compiler_risk"]
            )

            # Add noise and normalize
            if NUMPY_AVAILABLE:
                noise = np.random.normal(0, 0.1)
            else:
                import random

                noise = random.gauss(0, 0.1)
            target = max(0.0, min(vuln_prob + noise, 1.0))

            training_data.append(
                {
                    "features": features,
                    "target": target,
                }
            )

        self.model.train(training_data)

    @profile_ai_operation("vulnerability_prediction")
    def predict_vulnerability_likelihood(self, file_context: dict[str, Any]) -> PredictionResult:
        """Predict likelihood of finding vulnerabilities."""
        features = self.feature_extractor.extract_vulnerability_features(file_context)

        predicted_likelihood, confidence_score = self.model.predict(features)

        # Determine confidence
        if confidence_score >= 0.7:
            confidence = PredictionConfidence.HIGH
        elif confidence_score >= 0.5:
            confidence = PredictionConfidence.MEDIUM
        else:
            confidence = PredictionConfidence.LOW

        # Generate reasoning
        reasoning = self._generate_vuln_reasoning(features, predicted_likelihood)

        error_bounds = (
            max(0.0, predicted_likelihood - 0.15),
            min(1.0, predicted_likelihood + 0.15),
        )

        return PredictionResult(
            prediction_id=str(uuid.uuid4()),
            prediction_type=PredictionType.VULNERABILITY_DISCOVERY,
            predicted_value=predicted_likelihood,
            confidence=confidence,
            confidence_score=confidence_score,
            factors=features,
            reasoning=reasoning,
            error_bounds=error_bounds,
        )

    def _generate_vuln_reasoning(self, features: dict[str, float], likelihood: float) -> str:
        """Generate reasoning for vulnerability prediction."""
        risk_factors = []

        if features.get("file_type_risk", 0.5) > 0.7:
            risk_factors.append("high-risk file type")

        if features.get("function_complexity", 0.5) > 0.7:
            risk_factors.append("high code complexity")

        if features.get("entropy", 0.5) > 0.8:
            risk_factors.append("high entropy (possible obfuscation)")

        if likelihood > 0.7:
            level = "High"
        elif likelihood > 0.4:
            level = "Moderate"
        else:
            level = "Low"

        if risk_factors:
            return f"{level} vulnerability likelihood due to {', '.join(risk_factors)}"
        return f"{level} vulnerability likelihood based on file analysis"

    def predict(self, binary_path: str) -> list[dict[str, Any]]:
        """Predict vulnerabilities for a binary file."""
        try:
            import os

            if not os.path.exists(binary_path):
                logger.warning("Binary file not found: %s", binary_path)
                return []

            file_context = {
                "file_extension": os.path.splitext(binary_path)[1],
                "file_size": os.path.getsize(binary_path),
                "binary_path": binary_path,
            }

            result = self.predict_vulnerability_likelihood(file_context)

            return [
                {
                    "type": "vulnerability_prediction",
                    "likelihood": result.predicted_value,
                    "confidence": result.confidence_score,
                    "reasoning": result.reasoning,
                    "factors": result.factors,
                }
            ]

        except Exception as e:
            logger.error("Error predicting vulnerabilities for %s: %s", binary_path, e)
            return []

    def get_confidence_score(self, binary_path: str) -> float:
        """Get confidence score for vulnerability predictions."""
        try:
            import os

            if not os.path.exists(binary_path):
                logger.warning("Binary file not found: %s", binary_path)
                return 0.0

            file_context = {
                "file_extension": os.path.splitext(binary_path)[1],
                "file_size": os.path.getsize(binary_path),
                "binary_path": binary_path,
            }

            result = self.predict_vulnerability_likelihood(file_context)
            return result.confidence_score

        except Exception as e:
            logger.error("Error getting confidence score for %s: %s", binary_path, e)
            return 0.0


class PredictiveIntelligenceEngine:
    """Main predictive intelligence engine."""

    def __init__(self):
        """Initialize the predictive intelligence engine with specialized predictors."""
        self.success_predictor = SuccessProbabilityPredictor()
        self.time_predictor = ExecutionTimePredictor()
        self.vulnerability_predictor = VulnerabilityPredictor()

        self.prediction_cache: dict[str, PredictionResult] = {}
        self.prediction_history: deque = deque(maxlen=1000)

        # Performance tracking
        self.prediction_stats = {
            "total_predictions": 0,
            "cache_hits": 0,
            "accuracy_tracking": defaultdict(list),
        }

        logger.info("Predictive intelligence engine initialized")

    @profile_ai_operation("make_prediction")
    def make_prediction(
        self, prediction_type: PredictionType, context: dict[str, Any]
    ) -> PredictionResult:
        """Make a prediction of specified type."""
        # Check cache first
        cache_key = self._generate_cache_key(prediction_type, context)

        if cache_key in self.prediction_cache:
            cached_result = self.prediction_cache[cache_key]
            # Check if cache is still fresh (< 5 minutes)
            if (datetime.now() - cached_result.timestamp).seconds < 300:
                self.prediction_stats["cache_hits"] += 1
                return cached_result

        # Make new prediction
        if prediction_type == PredictionType.SUCCESS_PROBABILITY:
            result = self.success_predictor.predict_success_probability(
                context.get("operation_type", "unknown"),
                context,
            )
        elif prediction_type == PredictionType.EXECUTION_TIME:
            result = self.time_predictor.predict_execution_time(
                context.get("operation_type", "unknown"),
                context,
            )
        elif prediction_type == PredictionType.VULNERABILITY_DISCOVERY:
            result = self.vulnerability_predictor.predict_vulnerability_likelihood(context)
        else:
            # Default prediction for unsupported types
            result = PredictionResult(
                prediction_id=str(uuid.uuid4()),
                prediction_type=prediction_type,
                predicted_value=0.5,
                confidence=PredictionConfidence.LOW,
                confidence_score=0.3,
                factors={},
                reasoning="Prediction type not yet supported",
            )

        # Cache and track
        self.prediction_cache[cache_key] = result
        self.prediction_history.append(result)
        self.prediction_stats["total_predictions"] += 1

        return result

    def _generate_cache_key(self, prediction_type: PredictionType, context: dict[str, Any]) -> str:
        """Generate cache key for prediction."""
        import hashlib

        key_data = f"{prediction_type.value}_{json.dumps(context, sort_keys=True)}"
        return hashlib.md5(key_data.encode(), usedforsecurity=False).hexdigest()

    def verify_prediction_accuracy(self, prediction_id: str, actual_value: float):
        """Record actual outcome to improve accuracy tracking."""
        # Find prediction
        prediction = None
        for pred in self.prediction_history:
            if pred.prediction_id == prediction_id:
                prediction = pred
                break

        if not prediction:
            logger.warning(f"Prediction {prediction_id} not found for accuracy tracking")
            return

        # Calculate accuracy
        error = abs(prediction.predicted_value - actual_value)
        accuracy = max(0.0, 1.0 - error)

        # Track accuracy by prediction type
        self.prediction_stats["accuracy_tracking"][prediction.prediction_type.value].append(
            accuracy
        )

        # Update model with actual result
        if prediction.prediction_type == PredictionType.SUCCESS_PROBABILITY:
            self.success_predictor.model.update_model(
                {
                    "features": prediction.factors,
                    "target": actual_value,
                }
            )
        elif prediction.prediction_type == PredictionType.EXECUTION_TIME:
            self.time_predictor.model.update_model(
                {
                    "features": prediction.factors,
                    "target": actual_value,
                }
            )

        logger.info(
            f"Updated prediction accuracy for {prediction.prediction_type.value}: {accuracy:.3f}"
        )

    def get_prediction_analytics(self) -> dict[str, Any]:
        """Get analytics about prediction performance."""
        analytics = {
            "total_predictions": self.prediction_stats["total_predictions"],
            "cache_hit_rate": self.prediction_stats["cache_hits"]
            / max(1, self.prediction_stats["total_predictions"]),
            "recent_predictions": len(self.prediction_history),
            "accuracy_by_type": {},
        }

        # Calculate average accuracy by prediction type
        for pred_type, accuracies in self.prediction_stats["accuracy_tracking"].items():
            if accuracies:
                analytics["accuracy_by_type"][pred_type] = {
                    "avg_accuracy": sum(accuracies) / len(accuracies),
                    "sample_count": len(accuracies),
                    "recent_accuracy": sum(accuracies[-10:]) / min(10, len(accuracies)),
                }

        return analytics

    def get_prediction_insights(self) -> dict[str, Any]:
        """Get insights from prediction patterns."""
        insights = []

        # Analyze recent predictions
        if len(self.prediction_history) > 10:
            recent_predictions = list(self.prediction_history)[-10:]

            # Success rate trends
            success_predictions = [
                p
                for p in recent_predictions
                if p.prediction_type == PredictionType.SUCCESS_PROBABILITY
            ]
            if success_predictions:
                avg_success = sum(p.predicted_value for p in success_predictions) / len(
                    success_predictions
                )
                if avg_success > 0.8:
                    insights.append("Recent predictions show high success probability")
                elif avg_success < 0.6:
                    insights.append("Recent predictions show concerning success rates")

            # Time predictions
            time_predictions = [
                p for p in recent_predictions if p.prediction_type == PredictionType.EXECUTION_TIME
            ]
            if time_predictions:
                avg_time = sum(p.predicted_value for p in time_predictions) / len(time_predictions)
                if avg_time > 30:
                    insights.append("Recent operations predicted to be time-consuming")

        # Confidence analysis
        high_confidence_predictions = [
            p for p in self.prediction_history if p.confidence_score > 0.8
        ]
        confidence_rate = len(high_confidence_predictions) / max(1, len(self.prediction_history))

        if confidence_rate > 0.7:
            insights.append("High confidence in most predictions")
        elif confidence_rate < 0.3:
            insights.append("Low confidence in predictions - may need more training data")

        return {
            "insights": insights,
            "confidence_distribution": self._get_confidence_distribution(),
            "prediction_type_distribution": self._get_prediction_type_distribution(),
        }

    def _get_confidence_distribution(self) -> dict[str, int]:
        """Get distribution of confidence levels."""
        distribution = defaultdict(int)
        for prediction in self.prediction_history:
            distribution[prediction.confidence.value] += 1
        return dict(distribution)

    def _get_prediction_type_distribution(self) -> dict[str, int]:
        """Get distribution of prediction types."""
        distribution = defaultdict(int)
        for prediction in self.prediction_history:
            distribution[prediction.prediction_type.value] += 1
        return dict(distribution)


# Global predictive intelligence engine instance
predictive_intelligence = PredictiveIntelligenceEngine()
