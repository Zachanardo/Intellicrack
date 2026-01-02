"""Production tests for ML protection classifier.

Validates real protection scheme classification using trained Random Forest models.
Tests training, prediction, model persistence, and confidence scoring.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path

import joblib
import numpy as np
import pytest
from numpy import typing as npt
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

from intellicrack.core.ml.protection_classifier import (
    ClassificationResult,
    ProtectionClassifier,
)


class FakeFeatureExtractor:
    """Real test double for BinaryFeatureExtractor."""

    def __init__(self) -> None:
        self.feature_names: list[str] = [
            "overall_entropy",
            "text_entropy",
            "data_entropy",
            "num_sections",
            "avg_section_entropy",
            "ep_section_entropy",
            "suspicious_section_count",
            "import_count",
            "suspicious_import_ratio",
            "api_call_count",
            "known_packer_signatures",
            "timestamp_anomaly",
            "code_section_ratio",
            "data_section_ratio",
            "resource_section_size",
        ] + [f"opcode_freq_{i:02x}" for i in range(16)]

        self.extraction_calls: list[str | Path] = []
        self.next_features: npt.NDArray[np.float32] | None = None

    def extract_features(self, binary_path: str | Path) -> npt.NDArray[np.float32]:
        """Extract features from binary path.

        Args:
            binary_path: Path to binary file

        Returns:
            Feature vector as numpy array

        Raises:
            ValueError: If feature extraction fails
        """
        self.extraction_calls.append(binary_path)

        if self.next_features is not None:
            result = self.next_features
            self.next_features = None
            return result

        return np.random.rand(len(self.feature_names)).astype(np.float32)

    def set_next_features(self, features: npt.NDArray[np.float32]) -> None:
        """Set the next feature vector to return.

        Args:
            features: Feature vector to return on next call
        """
        self.next_features = features

    def reset_tracking(self) -> None:
        """Reset call tracking."""
        self.extraction_calls.clear()
        self.next_features = None


@pytest.fixture
def fake_extractor() -> FakeFeatureExtractor:
    """Create a fake feature extractor for testing.

    Returns:
        Configured FakeFeatureExtractor instance
    """
    return FakeFeatureExtractor()


class TestProtectionClassifierInitialization:
    """Tests for classifier initialization and setup."""

    def test_initialization_without_model(self, tmp_path: Path) -> None:
        model_path = tmp_path / "test_model"
        classifier = ProtectionClassifier(model_path=model_path)

        assert classifier.model_path == model_path
        assert classifier.model_file == model_path / "model.pkl"
        assert classifier.scaler_file == model_path / "scaler.pkl"
        assert classifier.encoder_file == model_path / "encoder.pkl"
        assert classifier.model is None

    def test_initialization_with_existing_model(self, tmp_path: Path) -> None:
        model_path = tmp_path / "test_model"
        model_path.mkdir(parents=True, exist_ok=True)

        model = RandomForestClassifier(n_estimators=10)
        scaler = StandardScaler()
        encoder = LabelEncoder()

        X_dummy = np.random.rand(10, 5)
        y_dummy = np.array(["VMProtect", "Themida"] * 5)

        encoder.fit(y_dummy)
        scaler.fit(X_dummy)
        model.fit(X_dummy, encoder.transform(y_dummy))

        joblib.dump(model, model_path / "model.pkl")
        joblib.dump(scaler, model_path / "scaler.pkl")
        joblib.dump(encoder, model_path / "encoder.pkl")

        classifier = ProtectionClassifier(model_path=model_path)

        assert classifier.model is not None
        assert classifier.scaler is not None
        assert classifier.label_encoder is not None

    def test_protection_schemes_defined(self) -> None:
        assert "VMProtect" in ProtectionClassifier.PROTECTION_SCHEMES
        assert "Themida" in ProtectionClassifier.PROTECTION_SCHEMES
        assert "Enigma" in ProtectionClassifier.PROTECTION_SCHEMES
        assert "None" in ProtectionClassifier.PROTECTION_SCHEMES


class TestModelTraining:
    """Tests for model training functionality."""

    def test_train_basic(self) -> None:
        classifier = ProtectionClassifier()

        n_samples = 100
        n_features = 20

        X = np.random.rand(n_samples, n_features)
        y = np.random.choice(["VMProtect", "Themida", "Enigma", "None"], n_samples)

        results = classifier.train(X, y, test_size=0.2, n_estimators=50, cross_validate=False)

        assert results["train_accuracy"] > 0
        assert results["test_accuracy"] > 0
        assert results["n_samples"] == n_samples
        assert results["n_features"] == n_features
        assert classifier.model is not None
        assert classifier.scaler is not None
        assert classifier.label_encoder is not None

    def test_train_with_cross_validation(self) -> None:
        classifier = ProtectionClassifier()

        n_samples = 150
        n_features = 25

        X = np.random.rand(n_samples, n_features)
        y = np.random.choice(["VMProtect", "Themida", "Enigma"], n_samples)

        results = classifier.train(X, y, cross_validate=True, n_estimators=30)

        assert "cv_mean_accuracy" in results
        assert "cv_std_accuracy" in results
        assert 0.0 <= results["cv_mean_accuracy"] <= 1.0

    def test_train_creates_proper_model(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(80, 15)
        y = np.array(["VMProtect"] * 40 + ["Themida"] * 40)

        classifier.train(X, y, n_estimators=20, cross_validate=False)

        assert isinstance(classifier.model, RandomForestClassifier)
        assert classifier.model.n_estimators == 20
        assert classifier.model.max_depth == 20

    def test_train_returns_confusion_matrix(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(60, 10)
        y = np.array(["VMProtect"] * 30 + ["Themida"] * 30)

        results = classifier.train(X, y, cross_validate=False)

        assert "confusion_matrix" in results
        assert isinstance(results["confusion_matrix"], list)

    def test_train_returns_classification_report(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(100, 15)
        y = np.array(["VMProtect"] * 50 + ["Themida"] * 50)

        results = classifier.train(X, y, cross_validate=False)

        assert "classification_report" in results
        assert isinstance(results["classification_report"], dict)

    def test_train_identifies_top_features(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(80, 20)
        y = np.array(["VMProtect"] * 40 + ["Themida"] * 40)

        results = classifier.train(X, y, cross_validate=False)

        assert "top_features" in results
        assert len(results["top_features"]) == 20
        assert all(isinstance(f, tuple) for f in results["top_features"])


class TestModelPrediction:
    """Tests for prediction functionality."""

    def test_predict_with_trained_model(
        self,
        tmp_path: Path,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X_train = np.random.rand(100, 15)
        y_train = np.array(["VMProtect"] * 50 + ["Themida"] * 50)

        classifier.train(X_train, y_train, cross_validate=False)

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 1000)

        fake_extractor.set_next_features(np.random.rand(15).astype(np.float32))
        result = classifier.predict(test_binary)

        assert isinstance(result, ClassificationResult)
        assert result.primary_protection in ["VMProtect", "Themida"]
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.top_predictions) > 0
        assert test_binary in fake_extractor.extraction_calls

    def test_predict_returns_top_predictions(
        self,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X_train = np.random.rand(120, 20)
        y_train = np.random.choice(["VMProtect", "Themida", "Enigma"], 120)

        classifier.train(X_train, y_train, cross_validate=False)

        fake_extractor.set_next_features(np.random.rand(20).astype(np.float32))
        result = classifier.predict("dummy_path")

        assert len(result.top_predictions) >= 3
        assert all(isinstance(pred, tuple) for pred in result.top_predictions)
        assert all(0.0 <= conf <= 1.0 for _, conf in result.top_predictions)
        assert "dummy_path" in fake_extractor.extraction_calls

    def test_predict_confidence_scores(
        self,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X_train = np.random.rand(100, 15)
        y_train = np.array(["VMProtect"] * 100)

        classifier.train(X_train, y_train, cross_validate=False)

        fake_extractor.set_next_features(np.random.rand(15).astype(np.float32))
        result = classifier.predict("dummy_path")

        assert result.confidence > 0.5

    def test_predict_without_trained_model_raises_error(self, tmp_path: Path) -> None:
        classifier = ProtectionClassifier()

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"MZ" + b"\x00" * 100)

        with pytest.raises((ValueError, AttributeError, RuntimeError)):
            classifier.predict(test_binary)


class TestModelPersistence:
    """Tests for saving and loading models."""

    def test_save_model(self, tmp_path: Path) -> None:
        model_path = tmp_path / "saved_model"
        classifier = ProtectionClassifier(model_path=model_path)

        X = np.random.rand(80, 10)
        y = np.array(["VMProtect"] * 40 + ["Themida"] * 40)

        classifier.train(X, y, cross_validate=False)
        classifier.save_model()

        assert (model_path / "model.pkl").exists()
        assert (model_path / "scaler.pkl").exists()
        assert (model_path / "encoder.pkl").exists()
        assert (model_path / "metadata.json").exists()

    def test_load_model(self, tmp_path: Path) -> None:
        model_path = tmp_path / "saved_model"
        classifier1 = ProtectionClassifier(model_path=model_path)

        X = np.random.rand(60, 10)
        y = np.array(["VMProtect"] * 30 + ["Themida"] * 30)

        classifier1.train(X, y, cross_validate=False)
        classifier1.save_model()

        classifier2 = ProtectionClassifier(model_path=model_path)

        assert classifier2.model is not None
        assert classifier2.scaler is not None
        assert classifier2.label_encoder is not None

    def test_save_and_load_preserves_predictions(
        self,
        tmp_path: Path,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        model_path = tmp_path / "saved_model"
        classifier1 = ProtectionClassifier(model_path=model_path)
        monkeypatch.setattr(classifier1, "feature_extractor", fake_extractor)

        X = np.random.rand(100, 15)
        y = np.array(["VMProtect"] * 50 + ["Themida"] * 50)

        classifier1.train(X, y, cross_validate=False)
        classifier1.save_model()

        test_features = np.random.rand(15).astype(np.float32)

        fake_extractor.set_next_features(test_features)
        result1 = classifier1.predict("test")

        classifier2 = ProtectionClassifier(model_path=model_path)
        fake_extractor2 = FakeFeatureExtractor()
        monkeypatch.setattr(classifier2, "feature_extractor", fake_extractor2)

        fake_extractor2.set_next_features(test_features)
        result2 = classifier2.predict("test")

        assert result1.primary_protection == result2.primary_protection
        assert abs(result1.confidence - result2.confidence) < 0.01


class TestClassificationResult:
    """Tests for classification result structure."""

    def test_classification_result_creation(self) -> None:
        feature_vector = np.array([0.1, 0.2, 0.3, 0.4, 0.5])

        result = ClassificationResult(
            primary_protection="VMProtect",
            confidence=0.85,
            top_predictions=[("VMProtect", 0.85), ("Themida", 0.10), ("Enigma", 0.05)],
            feature_vector=feature_vector,
            model_version="1.0.0",
        )

        assert result.primary_protection == "VMProtect"
        assert result.confidence == 0.85
        assert len(result.top_predictions) == 3
        assert np.array_equal(result.feature_vector, feature_vector)
        assert result.model_version == "1.0.0"


class TestRealWorldScenarios:
    """Tests simulating real protection classification scenarios."""

    def test_classify_vmprotect_binary(
        self,
        tmp_path: Path,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X = np.random.rand(200, 20)
        y = np.array(["VMProtect"] * 100 + ["Themida"] * 50 + ["Enigma"] * 50)

        classifier.train(X, y, n_estimators=100, cross_validate=False)

        vmprotect_features = np.random.rand(20).astype(np.float32)
        vmprotect_features[0] = 0.9
        vmprotect_features[1] = 0.8
        vmprotect_features[2] = 0.7

        fake_extractor.set_next_features(vmprotect_features)
        result = classifier.predict("vmprotect_sample.exe")

        assert result.primary_protection in classifier.PROTECTION_SCHEMES
        assert result.confidence > 0
        assert "vmprotect_sample.exe" in fake_extractor.extraction_calls

    def test_classify_multiple_binaries(
        self,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X = np.random.rand(150, 25)
        y = np.random.choice(["VMProtect", "Themida", "Enigma", "None"], 150)

        classifier.train(X, y, n_estimators=80, cross_validate=False)

        binaries = ["sample1.exe", "sample2.exe", "sample3.exe"]

        for binary in binaries:
            fake_extractor.set_next_features(np.random.rand(25).astype(np.float32))
            result = classifier.predict(binary)
            assert isinstance(result, ClassificationResult)
            assert result.primary_protection in classifier.PROTECTION_SCHEMES

        assert fake_extractor.extraction_calls == binaries


class TestModelAccuracy:
    """Tests for model accuracy and performance metrics."""

    def test_high_accuracy_with_separable_data(self) -> None:
        classifier = ProtectionClassifier()

        X_vmprotect = np.random.rand(50, 10) + np.array([1.0] * 10)
        X_themida = np.random.rand(50, 10) + np.array([0.0] * 10)

        X = np.vstack([X_vmprotect, X_themida])
        y = np.array(["VMProtect"] * 50 + ["Themida"] * 50)

        results = classifier.train(X, y, n_estimators=100, cross_validate=False)

        assert results["train_accuracy"] > 0.8
        assert results["test_accuracy"] > 0.6

    def test_model_handles_imbalanced_data(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(120, 15)
        y = np.array(["VMProtect"] * 100 + ["Themida"] * 20)

        results = classifier.train(X, y, cross_validate=False)

        assert results["train_accuracy"] > 0
        assert results["test_accuracy"] > 0


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_train_with_single_class(self) -> None:
        classifier = ProtectionClassifier()

        X = np.random.rand(50, 10)
        y = np.array(["VMProtect"] * 50)

        with pytest.raises(ValueError):
            classifier.train(X, y, cross_validate=False)

    def test_predict_with_wrong_feature_count(
        self,
        fake_extractor: FakeFeatureExtractor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        classifier = ProtectionClassifier()
        monkeypatch.setattr(classifier, "feature_extractor", fake_extractor)

        X = np.random.rand(80, 15)
        y = np.array(["VMProtect"] * 40 + ["Themida"] * 40)

        classifier.train(X, y, cross_validate=False)

        fake_extractor.set_next_features(np.random.rand(20).astype(np.float32))

        with pytest.raises(ValueError):
            classifier.predict("test")

    def test_train_with_empty_data(self) -> None:
        classifier = ProtectionClassifier()

        X = np.array([]).reshape(0, 10)
        y = np.array([])

        with pytest.raises(ValueError):
            classifier.train(X, y, cross_validate=False)
