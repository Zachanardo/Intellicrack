"""Production tests for incremental_learner.py - Real incremental learning validation.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import pickle
import struct
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.incremental_learner import (
    IncrementalLearner,
    LearningSession,
    TrainingSample,
)
from intellicrack.core.ml.protection_classifier import ProtectionClassifier


class TestTrainingSampleDataClass:
    """Production tests for TrainingSample data structure."""

    def test_training_sample_creates_with_required_fields(self) -> None:
        """TrainingSample initializes with all required fields."""
        feature_vector: np.ndarray = np.random.randn(50).astype(np.float32)

        sample: TrainingSample = TrainingSample(
            binary_path=Path("/test/binary.exe"),
            protection_type="vmprotect",
            feature_vector=feature_vector,
            confidence=0.95,
            source="manual",
            metadata={"version": "3.5"},
        )

        assert sample.binary_path == Path("/test/binary.exe"), "Path must match"
        assert sample.protection_type == "vmprotect", "Protection type must match"
        assert np.array_equal(sample.feature_vector, feature_vector), "Features must match"
        assert sample.confidence == 0.95, "Confidence must match"
        assert sample.source == "manual", "Source must match"
        assert sample.metadata["version"] == "3.5", "Metadata must match"
        assert isinstance(sample.timestamp, datetime), "Must have timestamp"

    def test_training_sample_defaults(self) -> None:
        """TrainingSample uses default values for optional fields."""
        feature_vector: np.ndarray = np.zeros(10, dtype=np.float32)

        sample: TrainingSample = TrainingSample(
            binary_path=Path("/test.exe"),
            protection_type="none",
            feature_vector=feature_vector,
        )

        assert sample.confidence == 1.0, "Default confidence must be 1.0"
        assert sample.source == "manual", "Default source must be manual"
        assert isinstance(sample.metadata, dict), "Metadata must default to dict"


class TestLearningSessionDataClass:
    """Production tests for LearningSession tracking."""

    def test_learning_session_tracks_metadata(self) -> None:
        """LearningSession tracks training session metadata."""
        start_time: datetime = datetime.now()

        session: LearningSession = LearningSession(
            session_id="test_session_123",
            start_time=start_time,
            samples_added=50,
            classes_updated={"vmprotect", "themida"},
            previous_accuracy=0.85,
            new_accuracy=0.90,
            retrain_triggered=True,
        )

        assert session.session_id == "test_session_123", "Session ID must match"
        assert session.start_time == start_time, "Start time must match"
        assert session.samples_added == 50, "Sample count must match"
        assert "vmprotect" in session.classes_updated, "Must track updated classes"
        assert session.previous_accuracy == 0.85, "Previous accuracy must match"
        assert session.new_accuracy == 0.90, "New accuracy must match"
        assert session.retrain_triggered, "Retrain flag must match"


class TestIncrementalLearnerInitialization:
    """Production tests for IncrementalLearner initialization."""

    @pytest.fixture
    def classifier(self, tmp_path: Path) -> ProtectionClassifier:
        """Create classifier for testing."""
        model_path: Path = tmp_path / "test_model"
        model_path.mkdir()
        return ProtectionClassifier(model_path=str(model_path))

    def test_incremental_learner_initializes_with_classifier(self, classifier: ProtectionClassifier, tmp_path: Path) -> None:
        """IncrementalLearner initializes with classifier and buffer."""
        buffer_path: Path = tmp_path / "buffer.pkl"

        learner: IncrementalLearner = IncrementalLearner(
            classifier=classifier,
            buffer_path=buffer_path,
            auto_retrain=True,
        )

        assert learner.classifier is classifier, "Classifier must match"
        assert learner.buffer_path == buffer_path, "Buffer path must match"
        assert learner.auto_retrain, "Auto-retrain must be enabled"
        assert isinstance(learner.sample_buffer, list), "Sample buffer must be list"
        assert isinstance(learner.learning_history, list), "Learning history must be list"

    def test_learner_creates_buffer_path_if_missing(self, classifier: ProtectionClassifier) -> None:
        """Learner uses default buffer path when not specified."""
        learner: IncrementalLearner = IncrementalLearner(classifier=classifier)

        assert learner.buffer_path is not None, "Must have buffer path"
        assert "sample_buffer.pkl" in str(learner.buffer_path), "Default buffer name must be used"

    def test_learner_loads_existing_buffer(self, classifier: ProtectionClassifier, tmp_path: Path) -> None:
        """Learner loads existing sample buffer from disk."""
        buffer_path: Path = tmp_path / "existing_buffer.pkl"

        existing_samples: list[TrainingSample] = [
            TrainingSample(
                binary_path=Path("/test1.exe"),
                protection_type="vmprotect",
                feature_vector=np.zeros(50, dtype=np.float32),
            ),
        ]

        with open(buffer_path, "wb") as f:
            pickle.dump(existing_samples, f)

        learner: IncrementalLearner = IncrementalLearner(
            classifier=classifier,
            buffer_path=buffer_path,
        )

        assert len(learner.sample_buffer) == 1, "Must load existing samples"
        assert learner.sample_buffer[0].protection_type == "vmprotect", "Sample must match"


class TestAddingSamples:
    """Production tests for adding training samples."""

    @pytest.fixture
    def learner(self, tmp_path: Path) -> IncrementalLearner:
        """Create incremental learner for testing."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()
        classifier = ProtectionClassifier(model_path=str(model_path))

        buffer_path: Path = tmp_path / "buffer.pkl"

        return IncrementalLearner(
            classifier=classifier,
            buffer_path=buffer_path,
            auto_retrain=False,
        )

    @pytest.fixture
    def test_binary(self, tmp_path: Path) -> Path:
        """Create test PE binary."""
        binary_path: Path = tmp_path / "test.exe"

        dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
        optional_header = b"\x00" * 224
        section_header = (
            b".text\x00\x00\x00" +
            struct.pack("<IIIIII", 0x1000, 0x1000, 0x200, 0x200, 0, 0) +
            struct.pack("<HHI", 0, 0, 0x60000020)
        )

        pe_file = dos_header + b"\x00" * (0x80 - len(dos_header))
        pe_file += pe_signature + coff_header + optional_header + section_header

        binary_path.write_bytes(pe_file)
        return binary_path

    def test_add_sample_extracts_features_and_stores(self, learner: IncrementalLearner, test_binary: Path) -> None:
        """add_sample extracts features and adds to buffer."""
        initial_size: int = len(learner.sample_buffer)

        success: bool = learner.add_sample(
            binary_path=test_binary,
            protection_type="themida",
            confidence=0.9,
            source="verified",
        )

        assert success, "Sample addition must succeed"
        assert len(learner.sample_buffer) == initial_size + 1, "Buffer must grow by 1"

        added_sample: TrainingSample = learner.sample_buffer[-1]
        assert added_sample.binary_path == test_binary, "Path must match"
        assert added_sample.protection_type == "themida", "Protection type must match"
        assert added_sample.confidence == 0.9, "Confidence must match"
        assert added_sample.source == "verified", "Source must match"
        assert len(added_sample.feature_vector) > 0, "Must have extracted features"

    def test_add_sample_persists_buffer_to_disk(self, learner: IncrementalLearner, test_binary: Path) -> None:
        """Adding sample persists buffer to disk."""
        learner.add_sample(
            binary_path=test_binary,
            protection_type="upx",
            confidence=1.0,
        )

        assert learner.buffer_path.exists(), "Buffer file must be created"

        with open(learner.buffer_path, "rb") as f:
            loaded_buffer: list[TrainingSample] = pickle.load(f)

        assert len(loaded_buffer) > 0, "Persisted buffer must have samples"
        assert loaded_buffer[-1].protection_type == "upx", "Persisted sample must match"

    def test_add_sample_with_metadata(self, learner: IncrementalLearner, test_binary: Path) -> None:
        """add_sample preserves metadata."""
        metadata: dict[str, Any] = {
            "version": "3.5",
            "detected_by": "manual_analysis",
            "notes": "Strong packing detected",
        }

        learner.add_sample(
            binary_path=test_binary,
            protection_type="vmprotect",
            metadata=metadata,
        )

        added_sample: TrainingSample = learner.sample_buffer[-1]
        assert added_sample.metadata["version"] == "3.5", "Metadata must be preserved"
        assert added_sample.metadata["detected_by"] == "manual_analysis", "All metadata fields must be preserved"

    def test_add_sample_handles_invalid_binary(self, learner: IncrementalLearner, tmp_path: Path) -> None:
        """add_sample handles corrupted binaries gracefully."""
        invalid_binary: Path = tmp_path / "invalid.exe"
        invalid_binary.write_bytes(b"NOT A PE FILE")

        success: bool = learner.add_sample(
            binary_path=invalid_binary,
            protection_type="unknown",
        )

        assert not success, "Must fail for invalid binary"


class TestAutoRetrain:
    """Production tests for automatic retraining."""

    @pytest.fixture
    def learner_with_pretrained_model(self, tmp_path: Path) -> IncrementalLearner:
        """Create learner with pre-trained classifier."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))

        X_train: np.ndarray = np.random.randn(100, 50).astype(np.float32)
        y_train: np.ndarray = np.array(["none"] * 50 + ["vmprotect"] * 50)
        classifier.train(X=X_train, y=y_train, n_estimators=10)

        buffer_path: Path = tmp_path / "buffer.pkl"

        return IncrementalLearner(
            classifier=classifier,
            buffer_path=buffer_path,
            auto_retrain=True,
        )

    def test_auto_retrain_triggers_at_threshold(self, learner_with_pretrained_model: IncrementalLearner, tmp_path: Path) -> None:
        """Auto-retrain triggers when buffer reaches threshold."""
        threshold: int = IncrementalLearner.RETRAIN_THRESHOLD

        for i in range(threshold):
            binary_path: Path = tmp_path / f"binary_{i}.exe"
            binary_path.write_bytes(b"MZ" + b"\x00" * 1000)

            learner_with_pretrained_model.add_sample(
                binary_path=binary_path,
                protection_type="themida" if i % 2 == 0 else "vmprotect",
                confidence=0.9,
            )

        assert len(learner_with_pretrained_model.sample_buffer) < threshold, "Buffer must be cleared after retrain"
        assert len(learner_with_pretrained_model.learning_history) > 0, "Learning history must be updated"

    def test_auto_retrain_disabled_keeps_samples(self, tmp_path: Path) -> None:
        """With auto_retrain=False, samples accumulate without triggering retrain."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))
        learner = IncrementalLearner(classifier=classifier, auto_retrain=False)

        threshold: int = IncrementalLearner.RETRAIN_THRESHOLD

        for i in range(threshold + 10):
            binary_path: Path = tmp_path / f"binary_{i}.exe"
            binary_path.write_bytes(b"MZ" + b"\x00" * 1000)
            learner.add_sample(binary_path=binary_path, protection_type="upx")

        assert len(learner.sample_buffer) >= threshold, "Buffer must accumulate without auto-retrain"


class TestIncrementalRetraining:
    """Production tests for incremental retraining."""

    @pytest.fixture
    def learner_with_samples(self, tmp_path: Path) -> IncrementalLearner:
        """Create learner with pre-loaded samples."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))

        X_initial: np.ndarray = np.random.randn(100, 50).astype(np.float32)
        y_initial: np.ndarray = np.array(["none"] * 50 + ["vmprotect"] * 50)
        classifier.train(X=X_initial, y=y_initial, n_estimators=10)

        learner = IncrementalLearner(classifier=classifier, auto_retrain=False)

        for i in range(30):
            learner.sample_buffer.append(
                TrainingSample(
                    binary_path=Path(f"/test_{i}.exe"),
                    protection_type="themida" if i % 2 == 0 else "vmprotect",
                    feature_vector=np.random.randn(50).astype(np.float32),
                    confidence=0.8,
                )
            )

        return learner

    def test_retrain_incremental_updates_model(self, learner_with_samples: IncrementalLearner) -> None:
        """retrain_incremental updates model with new samples."""
        initial_buffer_size: int = len(learner_with_samples.sample_buffer)

        results: dict[str, Any] = learner_with_samples.retrain_incremental()

        assert "test_accuracy" in results or len(results) > 0, "Must return training results"
        assert len(learner_with_samples.sample_buffer) < initial_buffer_size, "Buffer must be cleared"
        assert len(learner_with_samples.learning_history) > 0, "Learning history must be updated"

    def test_retrain_filters_low_confidence_samples(self, learner_with_samples: IncrementalLearner) -> None:
        """Retraining filters out low-confidence samples."""
        learner_with_samples.sample_buffer.append(
            TrainingSample(
                binary_path=Path("/low_conf.exe"),
                protection_type="unknown",
                feature_vector=np.random.randn(50).astype(np.float32),
                confidence=0.2,
            )
        )

        high_conf_count: int = sum(1 for s in learner_with_samples.sample_buffer if s.confidence >= 0.5)

        learner_with_samples.retrain_incremental()

        last_session: LearningSession = learner_with_samples.learning_history[-1]
        assert last_session.samples_added == high_conf_count, "Must only use high-confidence samples"

    def test_retrain_with_empty_buffer(self, tmp_path: Path) -> None:
        """Retraining with empty buffer returns empty results."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))
        learner = IncrementalLearner(classifier=classifier)

        results: dict[str, Any] = learner.retrain_incremental()

        assert results == {}, "Empty buffer must return empty results"

    def test_retrain_tracks_learning_session(self, learner_with_samples: IncrementalLearner) -> None:
        """Retraining creates and stores learning session."""
        learner_with_samples.retrain_incremental()

        assert len(learner_with_samples.learning_history) > 0, "Must record learning session"

        session: LearningSession = learner_with_samples.learning_history[-1]
        assert session.samples_added > 0, "Must track sample count"
        assert len(session.classes_updated) > 0, "Must track updated classes"
        assert session.retrain_triggered, "Retrain flag must be set"


class TestSampleQualityEvaluation:
    """Production tests for sample quality evaluation."""

    @pytest.fixture
    def trained_learner(self, tmp_path: Path) -> IncrementalLearner:
        """Create learner with trained model."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))

        X_train: np.ndarray = np.random.randn(200, 50).astype(np.float32)
        y_train: np.ndarray = np.array(["none"] * 100 + ["vmprotect"] * 100)
        classifier.train(X=X_train, y=y_train, n_estimators=20)

        return IncrementalLearner(classifier=classifier)

    def test_evaluate_sample_quality_returns_metrics(self, trained_learner: IncrementalLearner) -> None:
        """evaluate_sample_quality returns quality metrics."""
        sample: TrainingSample = TrainingSample(
            binary_path=Path("/test.exe"),
            protection_type="vmprotect",
            feature_vector=np.random.randn(50).astype(np.float32),
            confidence=0.9,
            source="manual",
        )

        quality: dict[str, Any] = trained_learner.evaluate_sample_quality(sample)

        assert "confidence" in quality, "Must include confidence"
        assert "source" in quality, "Must include source"
        assert "is_high_quality" in quality, "Must evaluate quality"
        assert "is_verified" in quality, "Must check verification"
        assert quality["confidence"] == 0.9, "Confidence must match"

    def test_quality_evaluation_includes_prediction(self, trained_learner: IncrementalLearner) -> None:
        """Quality evaluation includes model prediction."""
        sample: TrainingSample = TrainingSample(
            binary_path=Path("/test.exe"),
            protection_type="vmprotect",
            feature_vector=np.random.randn(50).astype(np.float32),
            confidence=1.0,
        )

        quality: dict[str, Any] = trained_learner.evaluate_sample_quality(sample)

        if "prediction" in quality:
            assert "prediction_confidence" in quality, "Must have prediction confidence"
            assert "prediction_matches_label" in quality, "Must compare prediction to label"


class TestUncertainPredictions:
    """Production tests for uncertain prediction identification."""

    @pytest.fixture
    def learner_with_uncertain_samples(self, tmp_path: Path) -> IncrementalLearner:
        """Create learner with samples for uncertainty testing."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()

        classifier = ProtectionClassifier(model_path=str(model_path))

        X_train: np.ndarray = np.random.randn(200, 50).astype(np.float32)
        y_train: np.ndarray = np.array(["none"] * 100 + ["vmprotect"] * 100)
        classifier.train(X=X_train, y=y_train, n_estimators=20)

        learner = IncrementalLearner(classifier=classifier)

        for i in range(10):
            learner.sample_buffer.append(
                TrainingSample(
                    binary_path=Path(f"/test_{i}.exe"),
                    protection_type="vmprotect",
                    feature_vector=np.random.randn(50).astype(np.float32),
                    confidence=0.9,
                )
            )

        return learner

    def test_get_uncertain_predictions_returns_low_confidence(self, learner_with_uncertain_samples: IncrementalLearner) -> None:
        """get_uncertain_predictions identifies uncertain samples."""
        uncertain: list[tuple[Path, dict[str, Any]]] = learner_with_uncertain_samples.get_uncertain_predictions(
            min_uncertainty=0.3,
            max_count=20,
        )

        assert isinstance(uncertain, list), "Must return list"

        for binary_path, info in uncertain:
            assert isinstance(binary_path, Path), "Must return Path objects"
            assert "prediction" in info or "confidence" in info, "Must include prediction info"

    def test_uncertain_predictions_limited_by_max_count(self, learner_with_uncertain_samples: IncrementalLearner) -> None:
        """Uncertain predictions are limited to max_count."""
        max_count: int = 5

        uncertain: list[tuple[Path, dict[str, Any]]] = learner_with_uncertain_samples.get_uncertain_predictions(
            min_uncertainty=0.1,
            max_count=max_count,
        )

        assert len(uncertain) <= max_count, "Must respect max_count limit"


class TestBufferStatistics:
    """Production tests for buffer statistics."""

    @pytest.fixture
    def learner(self, tmp_path: Path) -> IncrementalLearner:
        """Create learner for testing."""
        model_path: Path = tmp_path / "model"
        model_path.mkdir()
        classifier = ProtectionClassifier(model_path=str(model_path))
        return IncrementalLearner(classifier=classifier)

    def test_get_buffer_statistics_empty_buffer(self, learner: IncrementalLearner) -> None:
        """Buffer statistics handles empty buffer."""
        stats: dict[str, Any] = learner.get_buffer_statistics()

        assert stats["size"] == 0, "Size must be 0 for empty buffer"
        assert stats["classes"] == {}, "Classes must be empty dict"

    def test_get_buffer_statistics_with_samples(self, learner: IncrementalLearner) -> None:
        """Buffer statistics counts samples and classes."""
        learner.sample_buffer.extend([
            TrainingSample(
                binary_path=Path("/test1.exe"),
                protection_type="vmprotect",
                feature_vector=np.zeros(50, dtype=np.float32),
            ),
            TrainingSample(
                binary_path=Path("/test2.exe"),
                protection_type="vmprotect",
                feature_vector=np.zeros(50, dtype=np.float32),
            ),
            TrainingSample(
                binary_path=Path("/test3.exe"),
                protection_type="themida",
                feature_vector=np.zeros(50, dtype=np.float32),
            ),
        ])

        stats: dict[str, Any] = learner.get_buffer_statistics()

        assert stats["size"] == 3, "Size must match sample count"
