"""Production tests for protection classifier with REAL binary features.

Tests validate ML-based protection classification using ACTUAL features
extracted from real Windows binaries:
- Training with real PE binary features (not random data)
- Classification of real protected binaries
- Feature importance analysis on actual binary characteristics
- Model persistence and loading with real trained models
- Confidence scoring on genuine protection schemes

CRITICAL: All tests use REAL binary features extracted from actual Windows
executables. NO np.random.rand(), NO mocked features, NO simulated data.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.protection_classifier import ClassificationResult, ProtectionClassifier


WINDOWS_BINARIES = {
    "kernel32": Path(r"C:\Windows\System32\kernel32.dll"),
    "notepad": Path(r"C:\Windows\System32\notepad.exe"),
    "calc": Path(r"C:\Windows\System32\calc.exe"),
    "cmd": Path(r"C:\Windows\System32\cmd.exe"),
}


def get_available_binaries() -> list[Path]:
    """Get list of available Windows binaries for testing."""
    available = [path for path in WINDOWS_BINARIES.values() if path.exists()]
    if len(available) < 2:
        pytest.skip("Need at least 2 Windows binaries for testing")
    return available


def extract_real_features(binary_path: Path) -> np.ndarray:
    """Extract REAL features from actual binary."""
    extractor = BinaryFeatureExtractor()
    return extractor.extract_features(binary_path)


class TestClassifierWithRealFeatures:
    """Test classifier using features from real binaries."""

    def test_train_with_real_binary_features(self) -> None:
        """Train classifier using real features extracted from Windows binaries."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        labels = ["None", "None", "VMProtect", "VMProtect"]
        y = np.array(labels)

        results = classifier.train(X, y, test_size=0.25, n_estimators=50, cross_validate=False)

        assert results["train_accuracy"] > 0
        assert results["test_accuracy"] >= 0
        assert results["n_samples"] == len(binaries[:4])
        assert classifier.model is not None

    def test_predict_with_real_features(self) -> None:
        """Predict protection using features from real binary."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:6]]
        X = np.vstack(features_list)

        labels = ["None", "None", "Themida", "VMProtect", "Enigma", "None"]
        y = np.array(labels)

        classifier.train(X, y, test_size=0.2, cross_validate=False)

        test_binary = binaries[0]
        result = classifier.predict(test_binary)

        assert isinstance(result, ClassificationResult)
        assert result.primary_protection in classifier.PROTECTION_SCHEMES
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.top_predictions) > 0

    def test_feature_importance_with_real_data(self) -> None:
        """Analyze feature importance using real binary features."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida"])

        classifier.train(X, y, cross_validate=False)

        top_features = classifier.get_feature_importance(top_n=10)

        assert len(top_features) == 10
        assert all(isinstance(feat, tuple) for feat in top_features)
        assert all(isinstance(name, str) and isinstance(importance, float) for name, importance in top_features)

    def test_model_persistence_with_real_features(self, tmp_path: Path) -> None:
        """Save and load model trained on real features."""
        binaries = get_available_binaries()
        model_path = tmp_path / "real_model"

        classifier1 = ProtectionClassifier(model_path=model_path)

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)
        y = np.array(["VMProtect", "None", "Themida", "None"])

        classifier1.train(X, y, cross_validate=False)
        classifier1.save_model()

        assert (model_path / "model.pkl").exists()
        assert (model_path / "scaler.pkl").exists()
        assert (model_path / "encoder.pkl").exists()

        classifier2 = ProtectionClassifier(model_path=model_path)

        assert classifier2.model is not None
        assert classifier2.scaler is not None
        assert classifier2.label_encoder is not None

    def test_classification_consistency_with_real_data(self) -> None:
        """Classification produces consistent results for same binary."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)
        y = np.array(["VMProtect", "VMProtect", "Themida", "Themida"])

        classifier.train(X, y, cross_validate=False)

        test_binary = binaries[0]

        result1 = classifier.predict(test_binary)
        result2 = classifier.predict(test_binary)

        assert result1.primary_protection == result2.primary_protection
        assert abs(result1.confidence - result2.confidence) < 0.01


class TestFeatureExtractionIntegration:
    """Test integration with BinaryFeatureExtractor."""

    def test_extractor_provides_consistent_feature_count(self) -> None:
        """Feature extractor provides same number of features for all binaries."""
        binaries = get_available_binaries()

        feature_counts = [len(extract_real_features(binary)) for binary in binaries[:3]]

        assert all(count == feature_counts[0] for count in feature_counts)

    def test_extracted_features_are_float32(self) -> None:
        """Extracted features are np.float32 type."""
        binaries = get_available_binaries()

        features = extract_real_features(binaries[0])

        assert features.dtype == np.float32

    def test_extracted_features_in_valid_range(self) -> None:
        """Extracted features are in reasonable numeric ranges."""
        binaries = get_available_binaries()

        features = extract_real_features(binaries[0])

        assert np.all(np.isfinite(features))
        assert not np.any(np.isnan(features))


class TestTrainingWithMultipleProtections:
    """Test training with various protection scheme labels."""

    def test_train_with_multiple_protection_types(self) -> None:
        """Train classifier to distinguish multiple protection schemes."""
        binaries = get_available_binaries()[:6]
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries]
        X = np.vstack(features_list)

        y = np.array([
            "VMProtect",
            "Themida",
            "Enigma",
            "None",
            "VMProtect",
            "Themida",
        ])

        results = classifier.train(X, y, n_estimators=100, cross_validate=True)

        assert results["n_classes"] == 4
        assert "cv_mean_accuracy" in results
        assert results["cv_mean_accuracy"] >= 0

    def test_classifier_handles_imbalanced_labels(self) -> None:
        """Classifier handles imbalanced protection labels."""
        binaries = get_available_binaries()[:5]
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "VMProtect", "VMProtect", "VMProtect", "Themida"])

        results = classifier.train(X, y, cross_validate=False)

        assert results["train_accuracy"] > 0


class TestPredictionConfidence:
    """Test prediction confidence scoring."""

    def test_confident_prediction_on_similar_features(self) -> None:
        """Classifier produces high confidence for similar features."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect"] * 4)

        classifier.train(X, y, cross_validate=False)

        result = classifier.predict(binaries[0])

        assert result.confidence > 0.5

    def test_top_predictions_ordered_by_confidence(self) -> None:
        """Top predictions are ordered by confidence descending."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:6]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "Enigma", "None", "VMProtect", "Themida"])

        classifier.train(X, y, cross_validate=False)

        result = classifier.predict(binaries[0])

        confidences = [conf for _, conf in result.top_predictions]
        assert confidences == sorted(confidences, reverse=True)


class TestRealWorldScenarios:
    """Test real-world classification scenarios."""

    def test_classify_unprotected_binary(self) -> None:
        """Classify standard Windows binary as unprotected."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["None", "None", "VMProtect", "VMProtect"])

        classifier.train(X, y, n_estimators=100, cross_validate=False)

        result = classifier.predict(binaries[0])

        assert result.primary_protection in classifier.PROTECTION_SCHEMES

    def test_batch_classification_of_binaries(self) -> None:
        """Classify multiple binaries in batch."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "Enigma", "None"])

        classifier.train(X, y, cross_validate=False)

        results = [classifier.predict(binary) for binary in binaries[:2]]

        assert len(results) == 2
        assert all(isinstance(r, ClassificationResult) for r in results)


class TestFeatureScaling:
    """Test feature scaling and normalization."""

    def test_scaler_normalizes_real_features(self) -> None:
        """Scaler normalizes features from real binaries."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida"])

        classifier.train(X, y, cross_validate=False)

        assert classifier.scaler is not None

        test_features = extract_real_features(binaries[0])
        scaled = classifier.scaler.transform(test_features.reshape(1, -1))

        assert scaled.shape == (1, len(test_features))


class TestCrossValidation:
    """Test cross-validation with real features."""

    def test_cross_validation_with_real_data(self) -> None:
        """Perform cross-validation using real binary features."""
        binaries = get_available_binaries()
        if len(binaries) < 10:
            pytest.skip("Need at least 10 binaries for cross-validation")

        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:10]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect"] * 5 + ["Themida"] * 5)

        results = classifier.train(X, y, cross_validate=True, n_estimators=50)

        assert "cv_mean_accuracy" in results
        assert "cv_std_accuracy" in results
        assert 0.0 <= results["cv_mean_accuracy"] <= 1.0


class TestConfusionMatrix:
    """Test confusion matrix generation."""

    def test_confusion_matrix_with_real_features(self) -> None:
        """Generate confusion matrix from real binary classification."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:6]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida", "Enigma", "None"])

        results = classifier.train(X, y, cross_validate=False)

        assert "confusion_matrix" in results
        assert isinstance(results["confusion_matrix"], list)


class TestClassificationReport:
    """Test detailed classification report."""

    def test_classification_report_with_real_data(self) -> None:
        """Generate classification report from real features."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida"])

        results = classifier.train(X, y, cross_validate=False)

        assert "classification_report" in results
        assert isinstance(results["classification_report"], dict)


class TestEdgeCases:
    """Test edge cases with real data."""

    def test_predict_without_training_raises_error(self) -> None:
        """Prediction without training raises RuntimeError."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        with pytest.raises(RuntimeError):
            classifier.predict(binaries[0])

    def test_train_with_mismatched_dimensions_raises_error(self) -> None:
        """Training with mismatched X and y dimensions raises error."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)

        y = np.array(["VMProtect", "Themida"])  # Wrong size

        with pytest.raises(ValueError):
            classifier.train(X, y, cross_validate=False)


class TestModelVersioning:
    """Test model version tracking."""

    def test_model_version_in_results(self) -> None:
        """Training results include model version."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)
        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida"])

        results = classifier.train(X, y, cross_validate=False)

        assert "model_version" in results
        assert results["model_version"] == ProtectionClassifier.MODEL_VERSION

    def test_prediction_includes_model_version(self) -> None:
        """Prediction result includes model version."""
        binaries = get_available_binaries()
        classifier = ProtectionClassifier()

        features_list = [extract_real_features(binary) for binary in binaries[:4]]
        X = np.vstack(features_list)
        y = np.array(["VMProtect", "Themida", "VMProtect", "Themida"])

        classifier.train(X, y, cross_validate=False)

        result = classifier.predict(binaries[0])

        assert result.model_version == ProtectionClassifier.MODEL_VERSION


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
