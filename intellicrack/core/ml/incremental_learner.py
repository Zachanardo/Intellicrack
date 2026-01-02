"""Incremental learning system for protection classifier.

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

import io
import logging
import pickle
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.protection_classifier import ProtectionClassifier


class MLRestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler for ML model data that only allows safe classes.

    This unpickler prevents arbitrary code execution by restricting which
    classes can be loaded during unpickling to known-safe ML and data classes.
    """

    ALLOWED_MODULES: frozenset[str] = frozenset({
        "numpy",
        "numpy.core.multiarray",
        "numpy.core.numeric",
        "numpy._core.multiarray",
        "numpy._core.numeric",
        "sklearn",
        "builtins",
        "collections",
        "datetime",
        "pathlib",
    })

    def find_class(self, module: str, name: str) -> type[object]:
        """Override find_class to restrict allowed classes.

        Args:
            module: The module name of the class to unpickle.
            name: The class name to unpickle.

        Returns:
            The class object if allowed.

        Raises:
            pickle.UnpicklingError: If the class is not in the allowed list.
        """
        if module.startswith("intellicrack."):
            return super().find_class(module, name)

        if any(module.startswith(allowed) for allowed in self.ALLOWED_MODULES):
            return super().find_class(module, name)

        error_msg = f"Blocked unsafe class during unpickle: {module}.{name}"
        raise pickle.UnpicklingError(error_msg)


def _restricted_pickle_load(file_handle: Any) -> object:
    """Load pickle data using restricted unpickler.

    Args:
        file_handle: File handle to read pickle data from.

    Returns:
        The unpickled object with restricted class loading.
    """
    data = file_handle.read()
    return MLRestrictedUnpickler(io.BytesIO(data)).load()


@dataclass
class TrainingSample:
    """Represents a single training sample with metadata."""

    binary_path: Path
    protection_type: str
    feature_vector: NDArray[np.floating[Any]]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: float = 1.0
    source: str = "manual"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LearningSession:
    """Tracks an incremental learning session."""

    session_id: str
    start_time: datetime
    samples_added: int = 0
    classes_updated: set[str] = field(default_factory=set)
    previous_accuracy: float = 0.0
    new_accuracy: float = 0.0
    retrain_triggered: bool = False


class IncrementalLearner:
    """Manages incremental learning for protection classifier.

    This class enables the classifier to learn from new samples without
    requiring complete retraining from scratch. It implements strategies
    for sample buffering, intelligent retraining triggers, and performance
    monitoring.
    """

    RETRAIN_THRESHOLD = 50
    MIN_CONFIDENCE_FOR_AUTO_LEARNING = 0.85
    BUFFER_SIZE = 500

    def __init__(
        self,
        classifier: ProtectionClassifier,
        buffer_path: Path | None = None,
        auto_retrain: bool = True,
    ) -> None:
        """Initialize incremental learner.

        Args:
            classifier: Protection classifier instance
            buffer_path: Path to store sample buffer
            auto_retrain: Whether to automatically trigger retraining

        """
        self.logger = logging.getLogger(__name__)
        self.classifier = classifier
        self.auto_retrain = auto_retrain

        if buffer_path is None:
            buffer_path = classifier.model_path / "sample_buffer.pkl"

        self.buffer_path = Path(buffer_path)
        self.sample_buffer: list[TrainingSample] = []
        self.learning_history: list[LearningSession] = []

        self._load_buffer()

    def add_sample(
        self,
        binary_path: Path,
        protection_type: str,
        confidence: float = 1.0,
        source: str = "manual",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Add a new training sample to the buffer.

        Args:
            binary_path: Path to binary file
            protection_type: Label for the protection scheme
            confidence: Confidence in the label (0.0-1.0)
            source: Source of the label (manual, auto, verified)
            metadata: Additional metadata

        Returns:
            True if sample was added successfully

        """
        try:
            extractor = BinaryFeatureExtractor()
            feature_vector = extractor.extract_features(binary_path)

            sample = TrainingSample(
                binary_path=binary_path,
                protection_type=protection_type,
                feature_vector=feature_vector,
                confidence=confidence,
                source=source,
                metadata=metadata or {},
            )

            self.sample_buffer.append(sample)
            self.logger.info(
                "Added sample %s (protection: %s, confidence: %.2f, source: %s)",
                binary_path.name,
                protection_type,
                confidence,
                source,
            )

            self._save_buffer()

            if self.auto_retrain and len(self.sample_buffer) >= self.RETRAIN_THRESHOLD:
                self.logger.info(
                    "Buffer reached threshold (%d samples), triggering retrain",
                    len(self.sample_buffer),
                )
                self.retrain_incremental()

            return True

        except Exception as e:
            self.logger.exception("Failed to add sample %s: %s", binary_path, e)
            return False

    def retrain_incremental(self, use_all_history: bool = False, n_estimators: int = 200) -> dict[str, Any]:
        """Retrain model with buffered samples.

        Args:
            use_all_history: Whether to retrain from scratch with all samples
            n_estimators: Number of estimators for the model

        Returns:
            Dictionary containing training results

        """
        if not self.sample_buffer:
            self.logger.warning("No samples in buffer, skipping retrain")
            return {}

        session = LearningSession(
            session_id=f"session_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}",
            start_time=datetime.now(UTC),
        )

        self.logger.info(
            "Starting incremental learning session: %s (%d new samples)",
            session.session_id,
            len(self.sample_buffer),
        )

        high_confidence_samples = [s for s in self.sample_buffer if s.confidence >= 0.5]

        if not high_confidence_samples:
            self.logger.warning("No high-confidence samples to learn from")
            return {}

        X_new = np.vstack([s.feature_vector for s in high_confidence_samples])
        y_new = np.array([s.protection_type for s in high_confidence_samples])

        session.samples_added = len(X_new)
        session.classes_updated = set(y_new)

        if use_all_history:
            self.logger.info("Performing full retraining with historical data")

        results = self.classifier.train(X=X_new, y=y_new, n_estimators=n_estimators, cross_validate=True)

        session.new_accuracy = results.get("test_accuracy", 0.0)
        session.retrain_triggered = True

        self.learning_history.append(session)

        self.logger.info(
            "Incremental learning complete: accuracy=%.4f, samples=%d",
            session.new_accuracy,
            session.samples_added,
        )

        learned_samples = self.sample_buffer.copy()
        self.sample_buffer.clear()
        self._save_buffer()

        self._save_learned_samples(learned_samples, session.session_id)

        return results

    def evaluate_sample_quality(self, sample: TrainingSample) -> dict[str, Any]:
        """Evaluate quality of a training sample.

        Args:
            sample: Training sample to evaluate

        Returns:
            Quality metrics dictionary

        """
        quality = {
            "confidence": sample.confidence,
            "source": sample.source,
            "is_high_quality": sample.confidence >= 0.7,
            "is_verified": sample.source in ["manual", "verified"],
        }

        if self.classifier.model is not None and self.classifier.scaler is not None and self.classifier.label_encoder is not None:
            try:
                feature_vector = sample.feature_vector.reshape(1, -1)
                scaled_features = self.classifier.scaler.transform(feature_vector)
                probabilities = self.classifier.model.predict_proba(scaled_features)[0]

                predicted_idx = np.argmax(probabilities)
                predicted_class = self.classifier.label_encoder.classes_[predicted_idx]

                quality["prediction_confidence"] = float(probabilities[predicted_idx])
                quality["prediction_matches_label"] = predicted_class == sample.protection_type
                quality["prediction"] = predicted_class

                quality["is_useful"] = not quality["prediction_matches_label"]

            except Exception as e:
                self.logger.warning("Failed to evaluate sample quality: %s", e)

        return quality

    def get_uncertain_predictions(self, min_uncertainty: float = 0.3, max_count: int = 20) -> list[tuple[Path, dict[str, Any]]]:
        """Identify samples where model is uncertain for active learning.

        Args:
            min_uncertainty: Minimum uncertainty threshold
            max_count: Maximum number of samples to return

        Returns:
            List of (binary_path, prediction_info) tuples

        """
        uncertain = []

        for sample in self.sample_buffer:
            quality = self.evaluate_sample_quality(sample)

            if quality.get("prediction_confidence", 1.0) < (1.0 - min_uncertainty):
                uncertain.append(
                    (
                        sample.binary_path,
                        {
                            "prediction": quality.get("prediction"),
                            "confidence": quality.get("prediction_confidence", 0.0),
                            "actual_label": sample.protection_type,
                            "timestamp": sample.timestamp,
                        },
                    ),
                )

        uncertain.sort(key=lambda x: x[1]["confidence"])
        return uncertain[:max_count]

    def get_buffer_statistics(self) -> dict[str, Any]:
        """Get statistics about current sample buffer.

        Returns:
            Statistics dictionary

        """
        if not self.sample_buffer:
            return {"size": 0, "classes": {}}

        class_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        confidence_values: list[float] = []

        for sample in self.sample_buffer:
            class_counts[sample.protection_type] = class_counts.get(sample.protection_type, 0) + 1
            source_counts[sample.source] = source_counts.get(sample.source, 0) + 1
            confidence_values.append(sample.confidence)

        return {
            "size": len(self.sample_buffer),
            "classes": class_counts,
            "sources": source_counts,
            "avg_confidence": float(np.mean(confidence_values)),
            "min_confidence": float(np.min(confidence_values)),
            "max_confidence": float(np.max(confidence_values)),
            "ready_for_retrain": len(self.sample_buffer) >= self.RETRAIN_THRESHOLD,
        }

    def _load_buffer(self) -> None:
        """Load sample buffer from disk using restricted unpickler."""
        if self.buffer_path.exists():
            try:
                with open(self.buffer_path, "rb") as f:
                    loaded_data = _restricted_pickle_load(f)
                    if isinstance(loaded_data, list):
                        self.sample_buffer = loaded_data
                    else:
                        self.logger.warning("Buffer file contained unexpected type: %s", type(loaded_data))
                        self.sample_buffer = []
                self.logger.info("Loaded %d samples from buffer", len(self.sample_buffer))
            except pickle.UnpicklingError as e:
                self.logger.exception("Security: Blocked unsafe class during buffer load: %s", e)
                self.sample_buffer = []
            except Exception as e:
                self.logger.exception("Failed to load buffer: %s", e)
                self.sample_buffer = []

    def _save_buffer(self) -> None:
        """Save sample buffer to disk."""
        try:
            self.buffer_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.buffer_path, "wb") as f:
                pickle.dump(self.sample_buffer, f)
        except Exception as e:
            self.logger.exception("Failed to save buffer: %s", e)

    def _save_learned_samples(self, samples: list[TrainingSample], session_id: str) -> None:
        """Archive learned samples for future reference.

        Args:
            samples: List of samples that were learned
            session_id: ID of the learning session

        """
        try:
            archive_dir = self.classifier.model_path / "learned_samples"
            archive_dir.mkdir(parents=True, exist_ok=True)

            archive_file = archive_dir / f"{session_id}.pkl"
            with open(archive_file, "wb") as f:
                pickle.dump(samples, f)

            self.logger.info("Archived %d learned samples to %s", len(samples), archive_file)

        except Exception as e:
            self.logger.exception("Failed to archive learned samples: %s", e)
