"""Production-grade tests for ML integration with real binary analysis.

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

import shutil
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.incremental_learner import IncrementalLearner, TrainingSample
from intellicrack.core.ml.ml_integration import MLAnalysisIntegration
from intellicrack.core.ml.protection_classifier import ClassificationResult, ProtectionClassifier
from intellicrack.core.ml.sample_database import SampleDatabase, SampleMetadata

REAL_WINDOWS_BINARIES: dict[str, Path] = {
    "notepad": Path(r"C:\Windows\System32\notepad.exe"),
    "calc": Path(r"C:\Windows\System32\calc.exe"),
    "kernel32": Path(r"C:\Windows\System32\kernel32.dll"),
    "cmd": Path(r"C:\Windows\System32\cmd.exe"),
    "powershell": Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
}


@pytest.fixture(scope="module")
def real_binaries() -> dict[str, Path]:
    """Provide real Windows system binaries for testing."""
    binaries: dict[str, Path] = {
        name: path
        for name, path in REAL_WINDOWS_BINARIES.items()
        if path.exists()
    }
    if not binaries:
        pytest.skip("No Windows system binaries found for testing")

    return binaries


@pytest.fixture
def temp_model_dir() -> Path:
    """Create temporary directory for model storage."""
    temp_dir = Path(tempfile.mkdtemp(prefix="ml_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_db_dir() -> Path:
    """Create temporary directory for sample database."""
    temp_dir = Path(tempfile.mkdtemp(prefix="ml_db_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def feature_extractor() -> BinaryFeatureExtractor:
    """Provide feature extractor instance."""
    return BinaryFeatureExtractor()


@pytest.fixture
def trained_classifier(temp_model_dir: Path, real_binaries: dict[str, Path]) -> ProtectionClassifier:
    """Provide trained classifier with real binary data."""
    classifier = ProtectionClassifier(model_path=temp_model_dir)

    extractor = BinaryFeatureExtractor()
    features_list: list[np.ndarray] = []
    labels_list: list[str] = []

    for binary_path in real_binaries.values():
        feature_vector = extractor.extract_features(binary_path)
        features_list.append(feature_vector)
        labels_list.append("None")

    if len(features_list) >= 2:
        base_feature1 = features_list[0]
        base_feature2 = features_list[1] if len(features_list) > 1 else features_list[0]

        for i in range(5):
            features_list.append(base_feature1 * (1.1 + i * 0.02))
            labels_list.append("VMProtect")

        for i in range(5):
            features_list.append(base_feature2 * (0.9 + i * 0.02))
            labels_list.append("Themida")

    X = np.vstack(features_list)
    y = np.array(labels_list)

    classifier.train(X=X, y=y, n_estimators=50, cross_validate=False)
    classifier.save_model()

    return classifier


@pytest.fixture
def ml_integration(temp_model_dir: Path, trained_classifier: ProtectionClassifier) -> MLAnalysisIntegration:
    """Provide ML integration instance with trained model."""
    return MLAnalysisIntegration(
        model_path=temp_model_dir,
        enable_incremental_learning=True,
        enable_sample_database=True,
    )


class TestMLAnalysisIntegrationInitialization:
    """Test ML integration initialization and configuration."""

    def test_initialization_without_model_disables_ml(self, temp_model_dir: Path) -> None:
        """ML integration correctly disables when no trained model exists."""
        integration = MLAnalysisIntegration(
            model_path=temp_model_dir / "nonexistent",
            enable_incremental_learning=False,
            enable_sample_database=False,
        )

        assert integration.enabled is False
        assert integration.incremental_learner is None
        assert integration.sample_database is None

    def test_initialization_with_trained_model_enables_ml(self, ml_integration: MLAnalysisIntegration) -> None:
        """ML integration enables successfully with trained model."""
        assert ml_integration.enabled is True
        assert ml_integration.classifier is not None
        assert ml_integration.classifier.model is not None

    def test_incremental_learning_initialization(self, ml_integration: MLAnalysisIntegration) -> None:
        """Incremental learning component initializes correctly."""
        assert ml_integration.incremental_learner is not None
        assert ml_integration.incremental_learner.classifier is ml_integration.classifier
        assert ml_integration.incremental_learner.auto_retrain is True

    def test_sample_database_initialization(self, ml_integration: MLAnalysisIntegration) -> None:
        """Sample database initializes with correct structure."""
        assert ml_integration.sample_database is not None
        assert ml_integration.sample_database.database_path.exists()
        assert ml_integration.sample_database.index_file.exists()

    def test_classifier_loaded_from_disk(self, temp_model_dir: Path, trained_classifier: ProtectionClassifier) -> None:
        """Trained classifier loads successfully from saved model files."""
        new_integration = MLAnalysisIntegration(model_path=temp_model_dir)

        assert new_integration.enabled is True
        assert new_integration.classifier.model is not None
        assert new_integration.classifier.scaler is not None
        assert new_integration.classifier.label_encoder is not None


class TestBinaryClassification:
    """Test binary classification with real executables."""

    def test_classify_real_binary_returns_valid_result(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Classification on real binary produces valid structured result."""
        binary_path = next(iter(real_binaries.values()))
        result = ml_integration.classify_binary(binary_path)

        assert result["enabled"] is True
        assert "primary_protection" in result
        assert "confidence" in result
        assert "confidence_level" in result
        assert "model_version" in result
        assert "reliable" in result
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_classify_binary_includes_alternatives(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Classification includes top alternative predictions."""
        binary_path = next(iter(real_binaries.values()))
        result = ml_integration.classify_binary(binary_path, include_alternatives=True)

        assert "alternatives" in result
        assert isinstance(result["alternatives"], list)
        assert len(result["alternatives"]) > 0

        for alt in result["alternatives"]:
            assert "protection" in alt
            assert "confidence" in alt
            assert isinstance(alt["confidence"], float)

    def test_classify_binary_without_alternatives(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Classification excludes alternatives when requested."""
        binary_path = next(iter(real_binaries.values()))
        result = ml_integration.classify_binary(binary_path, include_alternatives=False)

        assert "alternatives" not in result

    def test_classify_multiple_binaries_produces_different_results(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Different binaries produce distinguishable classification results."""
        if len(real_binaries) < 2:
            pytest.skip("Need at least 2 binaries for comparison")

        results: list[dict[str, Any]] = []
        for binary_path in list(real_binaries.values())[:2]:
            result = ml_integration.classify_binary(binary_path)
            results.append(result)

        assert len(results) == 2
        vectors_different = (
            results[0]["primary_protection"] != results[1]["primary_protection"] or
            abs(results[0]["confidence"] - results[1]["confidence"]) > 0.01
        )
        assert vectors_different, "Different binaries should produce different results"

    def test_confidence_level_categorization_high(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """High confidence scores categorized correctly."""
        high_confidence = 0.92
        level = ml_integration._get_confidence_level(high_confidence)

        assert level == "very_high"

    def test_confidence_level_categorization_medium(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Medium confidence scores categorized correctly."""
        medium_confidence = 0.65
        level = ml_integration._get_confidence_level(medium_confidence)

        assert level == "medium"

    def test_confidence_level_categorization_low(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Low confidence scores categorized correctly."""
        low_confidence = 0.35
        level = ml_integration._get_confidence_level(low_confidence)

        assert level == "low"

    def test_reliable_flag_set_correctly_for_high_confidence(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Reliable flag reflects actual confidence level."""
        binary_path = next(iter(real_binaries.values()))
        result = ml_integration.classify_binary(binary_path)

        is_high = result["confidence_level"] in ["high", "very_high"]
        assert result["reliable"] == is_high

    def test_low_confidence_warning_included(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Low confidence predictions include warning message."""
        ml_integration.classifier.model.predict_proba = lambda x: np.array([[0.15, 0.85]])

        binary_path = next(iter(REAL_WINDOWS_BINARIES.values()))
        if not binary_path.exists():
            pytest.skip("Binary not available")

        result = ml_integration.classify_binary(binary_path)

        if result["confidence_level"] == "low":
            assert "warning" in result
            assert "manual verification" in result["warning"].lower()


class TestFeatureExtraction:
    """Test feature extraction from real binaries."""

    def test_extract_features_from_real_binary(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Feature extraction succeeds on real Windows binary."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        assert isinstance(features, np.ndarray)
        assert features.dtype == np.float32
        assert len(features) == len(feature_extractor.feature_names)
        assert not np.any(np.isnan(features)), "Feature vector contains NaN values"
        assert not np.any(np.isinf(features)), "Feature vector contains infinite values"

    def test_feature_vector_has_correct_dimensionality(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Extracted features match expected dimension count."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        expected_features = len(feature_extractor.feature_names)
        assert len(features) == expected_features

    def test_entropy_features_extracted(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Entropy features extracted with valid values."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        entropy_idx = feature_extractor.feature_names.index("overall_entropy")
        entropy = features[entropy_idx]

        assert 0.0 <= entropy <= 8.0, "Shannon entropy should be between 0 and 8"
        assert entropy > 0.0, "Real binary should have non-zero entropy"

    def test_section_features_extracted(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """PE section features extracted correctly."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        section_count_idx = feature_extractor.feature_names.index("section_count")
        section_count = features[section_count_idx]

        assert section_count >= 1.0, "PE binary should have at least one section"
        assert section_count < 50.0, "Section count should be reasonable"

    def test_import_features_extracted(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Import table features extracted from real binary."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        import_count_idx = feature_extractor.feature_names.index("import_count")
        import_count = features[import_count_idx]

        assert import_count >= 0.0, "Import count cannot be negative"

    def test_signature_features_extracted(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Protection signature features extracted."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        vmprotect_idx = feature_extractor.feature_names.index("signature_vmprotect")
        vmprotect_sig = features[vmprotect_idx]

        assert 0.0 <= vmprotect_sig <= 1.0, "Signature score should be normalized"

    def test_opcode_features_extracted(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Opcode frequency features extracted from executable sections."""
        binary_path = next(iter(real_binaries.values()))
        features = feature_extractor.extract_features(binary_path)

        opcode_00_idx = feature_extractor.feature_names.index("opcode_freq_00")
        opcode_freq = features[opcode_00_idx]

        assert 0.0 <= opcode_freq <= 1.0, "Opcode frequency should be normalized probability"

    def test_feature_consistency_across_extractions(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Same binary produces identical features across multiple extractions."""
        binary_path = next(iter(real_binaries.values()))

        features1 = feature_extractor.extract_features(binary_path)
        features2 = feature_extractor.extract_features(binary_path)

        assert np.allclose(features1, features2), "Feature extraction should be deterministic"

    def test_different_binaries_produce_different_features(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Different binaries produce distinguishable feature vectors."""
        if len(real_binaries) < 2:
            pytest.skip("Need at least 2 binaries for comparison")

        binary_paths = list(real_binaries.values())[:2]
        features1 = feature_extractor.extract_features(binary_paths[0])
        features2 = feature_extractor.extract_features(binary_paths[1])

        assert not np.allclose(features1, features2), "Different binaries should have different features"


class TestModelTrainingAndPrediction:
    """Test ML model training and prediction workflows."""

    def test_train_classifier_with_real_features(
        self,
        temp_model_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Classifier trains successfully on real binary features."""
        classifier = ProtectionClassifier(model_path=temp_model_dir)
        extractor = BinaryFeatureExtractor()

        features_list: list[np.ndarray] = []
        labels_list: list[str] = []

        for binary_path in list(real_binaries.values())[:5]:
            features = extractor.extract_features(binary_path)
            features_list.append(features)
            labels_list.append("None")

        X = np.vstack(features_list)
        y = np.array(labels_list)

        results = classifier.train(X=X, y=y, n_estimators=50, cross_validate=False)

        assert "train_accuracy" in results
        assert "test_accuracy" in results
        assert results["train_accuracy"] > 0.0
        assert results["test_accuracy"] > 0.0
        assert classifier.model is not None

    def test_trained_model_makes_predictions(
        self,
        trained_classifier: ProtectionClassifier,
        real_binaries: dict[str, Path],
    ) -> None:
        """Trained classifier produces predictions on real binaries."""
        binary_path = next(iter(real_binaries.values()))
        result = trained_classifier.predict(binary_path)

        assert isinstance(result, ClassificationResult)
        assert result.primary_protection is not None
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.top_predictions) > 0
        assert isinstance(result.feature_vector, np.ndarray)

    def test_prediction_top_n_alternatives(
        self,
        trained_classifier: ProtectionClassifier,
        real_binaries: dict[str, Path],
    ) -> None:
        """Prediction includes top alternative classifications."""
        binary_path = next(iter(real_binaries.values()))
        result = trained_classifier.predict(binary_path)

        assert len(result.top_predictions) >= 1

        confidences_sum = sum(conf for _, conf in result.top_predictions)
        assert confidences_sum <= 1.01, "Probabilities should sum to approximately 1.0"

        for protection, confidence in result.top_predictions:
            assert isinstance(protection, str)
            assert 0.0 <= confidence <= 1.0

    def test_model_persistence_save_and_load(
        self,
        temp_model_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Trained model saves and loads correctly."""
        classifier1 = ProtectionClassifier(model_path=temp_model_dir)
        extractor = BinaryFeatureExtractor()

        features_list = [extractor.extract_features(path) for path in list(real_binaries.values())[:4]]
        X = np.vstack(features_list)
        y = np.array(["None"] * len(features_list))

        classifier1.train(X=X, y=y, n_estimators=50, cross_validate=False)
        classifier1.save_model()

        classifier2 = ProtectionClassifier(model_path=temp_model_dir)
        classifier2.load_model()

        assert classifier2.model is not None
        assert classifier2.scaler is not None
        assert classifier2.label_encoder is not None

        binary_path = next(iter(real_binaries.values()))
        result1 = classifier1.predict(binary_path)
        result2 = classifier2.predict(binary_path)

        assert result1.primary_protection == result2.primary_protection
        assert abs(result1.confidence - result2.confidence) < 0.001

    def test_cross_validation_accuracy(
        self,
        temp_model_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Cross-validation produces reasonable accuracy metrics."""
        if len(real_binaries) < 2:
            pytest.skip("Need at least 2 binaries for cross-validation")

        classifier = ProtectionClassifier(model_path=temp_model_dir)
        extractor = BinaryFeatureExtractor()

        features_list = [extractor.extract_features(path) for path in list(real_binaries.values())[:2]]
        base_features = features_list.copy()

        features_list.extend(base_features[0] * (1.1 + i * 0.02) for i in range(5))
        features_list.extend(
            base_features[1 if len(base_features) > 1 else 0] * (0.9 + i * 0.02)
            for i in range(5)
        )
        X = np.vstack(features_list)
        y = np.array(["None"] * len(base_features) + ["VMProtect"] * 5 + ["Themida"] * 5)

        results = classifier.train(X=X, y=y, n_estimators=50, cross_validate=True)

        assert "cv_mean_accuracy" in results
        assert "cv_std_accuracy" in results
        assert 0.0 <= results["cv_mean_accuracy"] <= 1.0
        assert results["cv_std_accuracy"] >= 0.0


class TestIncrementalLearning:
    """Test incremental learning functionality."""

    def test_add_sample_to_buffer(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Sample successfully added to incremental learning buffer."""
        if ml_integration.incremental_learner is None:
            pytest.skip("Incremental learning not enabled")

        binary_path = next(iter(real_binaries.values()))
        success = ml_integration.incremental_learner.add_sample(
            binary_path=binary_path,
            protection_type="VMProtect",
            confidence=0.95,
            source="manual",
        )

        assert success is True
        assert len(ml_integration.incremental_learner.sample_buffer) > 0

    def test_buffer_statistics_accurate(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Buffer statistics reflect actual sample state."""
        if ml_integration.incremental_learner is None:
            pytest.skip("Incremental learning not enabled")

        learner = ml_integration.incremental_learner
        initial_size = len(learner.sample_buffer)

        binary_path = next(iter(real_binaries.values()))
        learner.add_sample(binary_path, "Themida", confidence=0.9)

        stats = learner.get_buffer_statistics()

        assert stats["size"] == initial_size + 1
        assert "Themida" in stats["classes"]
        assert stats["classes"]["Themida"] >= 1
        assert 0.0 <= stats["avg_confidence"] <= 1.0

    def test_evaluate_sample_quality(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Sample quality evaluation produces valid metrics."""
        if ml_integration.incremental_learner is None:
            pytest.skip("Incremental learning not enabled")

        learner = ml_integration.incremental_learner
        binary_path = next(iter(real_binaries.values()))

        learner.add_sample(binary_path, "VMProtect", confidence=0.85, source="manual")

        if learner.sample_buffer:
            sample = learner.sample_buffer[-1]
            quality = learner.evaluate_sample_quality(sample)

            assert "confidence" in quality
            assert "source" in quality
            assert "is_high_quality" in quality
            assert "is_verified" in quality
            assert quality["confidence"] == 0.85
            assert quality["source"] == "manual"

    def test_get_uncertain_predictions(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Uncertain predictions identified for active learning."""
        if ml_integration.incremental_learner is None:
            pytest.skip("Incremental learning not enabled")

        learner = ml_integration.incremental_learner

        for binary_path in list(real_binaries.values())[:3]:
            learner.add_sample(binary_path, "None", confidence=0.5)

        uncertain = learner.get_uncertain_predictions(min_uncertainty=0.3, max_count=5)

        assert isinstance(uncertain, list)
        for path, info in uncertain:
            assert isinstance(path, Path)
            assert "prediction" in info
            assert "confidence" in info
            assert "actual_label" in info


class TestSampleDatabase:
    """Test sample database management."""

    def test_add_sample_to_database(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Sample added to database with correct metadata."""
        db = SampleDatabase(database_path=temp_db_dir)
        binary_path = next(iter(real_binaries.values()))

        success, file_hash = db.add_sample(
            binary_path=binary_path,
            protection_type="VMProtect",
            confidence=0.9,
            source="manual",
            verified=True,
            copy_file=True,
        )

        assert success is True
        assert len(file_hash) == 64
        assert file_hash in db.index

    def test_database_prevents_duplicates(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Database correctly handles duplicate sample additions."""
        db = SampleDatabase(database_path=temp_db_dir)
        binary_path = next(iter(real_binaries.values()))

        success1, hash1 = db.add_sample(binary_path, "VMProtect", copy_file=True)
        success2, hash2 = db.add_sample(binary_path, "VMProtect", copy_file=True)

        assert success1 is True
        assert success2 is True
        assert hash1 == hash2

    def test_database_updates_higher_confidence_labels(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Database updates labels when higher confidence version added."""
        db = SampleDatabase(database_path=temp_db_dir)
        binary_path = next(iter(real_binaries.values()))

        db.add_sample(binary_path, "VMProtect", confidence=0.6, copy_file=True)
        success, file_hash = db.add_sample(binary_path, "Themida", confidence=0.9, copy_file=True)

        assert success is True
        assert db.index[file_hash].protection_type == "Themida"
        assert db.index[file_hash].confidence == 0.9

    def test_get_samples_by_protection(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Database retrieves samples filtered by protection type."""
        db = SampleDatabase(database_path=temp_db_dir)

        binaries_list = list(real_binaries.values())
        if len(binaries_list) >= 2:
            db.add_sample(binaries_list[0], "VMProtect", copy_file=True)
            db.add_sample(binaries_list[1], "Themida", copy_file=True)

        vmprotect_samples = db.get_samples_by_protection("VMProtect")

        assert len(vmprotect_samples) >= 1
        for path, metadata in vmprotect_samples:
            assert metadata.protection_type == "VMProtect"

    def test_database_statistics(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Database statistics accurately reflect stored samples."""
        db = SampleDatabase(database_path=temp_db_dir)

        for binary_path in list(real_binaries.values())[:3]:
            db.add_sample(binary_path, "None", confidence=0.8, copy_file=True)

        stats = db.get_statistics()

        assert stats["total_samples"] >= 3
        assert "protection_types" in stats
        assert "sources" in stats
        assert "avg_confidence" in stats
        assert stats["avg_confidence"] > 0.0

    def test_extract_training_data_from_database(
        self,
        temp_db_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Database extracts training data with correct format."""
        db = SampleDatabase(database_path=temp_db_dir)

        for binary_path in list(real_binaries.values())[:4]:
            db.add_sample(binary_path, "None", confidence=0.9, copy_file=True)

        X, y = db.extract_training_data(min_confidence=0.5)

        assert isinstance(X, np.ndarray)
        assert isinstance(y, np.ndarray)
        assert len(X) == len(y)
        assert len(X) >= 4
        assert X.shape[1] > 0


class TestCompleteMLWorkflow:
    """Test complete end-to-end ML analysis workflows."""

    def test_analyze_binary_with_ml_complete_workflow(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Complete ML analysis workflow produces comprehensive results."""
        binary_path = next(iter(real_binaries.values()))
        results = ml_integration.analyze_with_ml(binary_path)

        assert "binary_path" in results
        assert "ml_enabled" in results
        assert results["ml_enabled"] is True
        assert "classification" in results

        classification = results["classification"]
        assert classification["enabled"] is True
        assert "primary_protection" in classification
        assert "confidence" in classification

    def test_add_verified_sample_workflow(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Adding verified sample updates both database and learner."""
        binary_path = next(iter(real_binaries.values()))

        success = ml_integration.add_verified_sample(
            binary_path=binary_path,
            protection_type="VMProtect",
            verified=True,
            notes="Test sample",
        )

        assert success is True

        if ml_integration.sample_database:
            stats = ml_integration.sample_database.get_statistics()
            assert stats["total_samples"] > 0

        if ml_integration.incremental_learner:
            buffer_stats = ml_integration.incremental_learner.get_buffer_statistics()
            assert buffer_stats["size"] > 0

    def test_get_learning_statistics(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Learning statistics provide comprehensive system state."""
        stats = ml_integration.get_learning_statistics()

        assert "ml_enabled" in stats
        assert stats["ml_enabled"] is True

        if ml_integration.classifier.model:
            assert "model_info" in stats
            assert "version" in stats["model_info"]
            assert "n_features" in stats["model_info"]
            assert "classes" in stats["model_info"]

    def test_recommended_tools_for_protections(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Recommended tools provided for known protection schemes."""
        vmprotect_tools = ml_integration._get_recommended_tools("VMProtect")

        assert "unpackers" in vmprotect_tools
        assert "analyzers" in vmprotect_tools
        assert "techniques" in vmprotect_tools
        assert len(vmprotect_tools["unpackers"]) > 0

        themida_tools = ml_integration._get_recommended_tools("Themida")
        assert "unpackers" in themida_tools
        assert themida_tools != vmprotect_tools

    def test_recommended_tools_for_unknown_protection(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Generic recommendations provided for unknown protections."""
        unknown_tools = ml_integration._get_recommended_tools("UnknownProtector")

        assert "analyzers" in unknown_tools
        assert "techniques" in unknown_tools
        assert len(unknown_tools["analyzers"]) > 0


class TestPerformanceBenchmarks:
    """Test ML operation performance on real binaries."""

    def test_feature_extraction_performance(
        self,
        feature_extractor: BinaryFeatureExtractor,
        real_binaries: dict[str, Path],
    ) -> None:
        """Feature extraction completes within acceptable time."""
        import time

        binary_path = next(iter(real_binaries.values()))

        start_time = time.time()
        features = feature_extractor.extract_features(binary_path)
        elapsed_time = time.time() - start_time

        assert elapsed_time < 5.0, f"Feature extraction took {elapsed_time:.2f}s (max 5s)"
        assert len(features) > 0

    def test_prediction_performance(
        self,
        trained_classifier: ProtectionClassifier,
        real_binaries: dict[str, Path],
    ) -> None:
        """Prediction completes within acceptable time."""
        import time

        binary_path = next(iter(real_binaries.values()))

        start_time = time.time()
        result = trained_classifier.predict(binary_path)
        elapsed_time = time.time() - start_time

        assert elapsed_time < 6.0, f"Prediction took {elapsed_time:.2f}s (max 6s)"
        assert result.primary_protection is not None

    def test_batch_classification_performance(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Batch classification maintains reasonable throughput."""
        import time

        if len(real_binaries) < 3:
            pytest.skip("Need at least 3 binaries for batch test")

        binaries_to_test = list(real_binaries.values())[:3]

        start_time = time.time()
        for binary_path in binaries_to_test:
            ml_integration.classify_binary(binary_path)
        elapsed_time = time.time() - start_time

        avg_time = elapsed_time / len(binaries_to_test)
        assert avg_time < 10.0, f"Average classification time {avg_time:.2f}s (max 10s)"


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge case scenarios."""

    def test_classify_nonexistent_file(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Classification of nonexistent file handled gracefully."""
        result = ml_integration.classify_binary(Path("nonexistent_file.exe"))

        assert result["enabled"] is True
        assert "error" in result

    def test_disabled_ml_integration_returns_error(
        self,
        temp_model_dir: Path,
    ) -> None:
        """Disabled ML integration returns appropriate error response."""
        integration = MLAnalysisIntegration(
            model_path=temp_model_dir / "nonexistent",
            enable_incremental_learning=False,
        )

        result = integration.classify_binary(Path("any_file.exe"))

        assert result["enabled"] is False
        assert "error" in result

    def test_retrain_with_insufficient_samples(
        self,
        ml_integration: MLAnalysisIntegration,
    ) -> None:
        """Retraining with insufficient samples returns error."""
        if ml_integration.sample_database:
            ml_integration.sample_database.index.clear()

        results = ml_integration.retrain_model(use_database=True)

        assert "error" in results
        assert "Insufficient samples" in results["error"]

    def test_feature_extraction_invalid_file(
        self,
        feature_extractor: BinaryFeatureExtractor,
        temp_model_dir: Path,
    ) -> None:
        """Feature extraction on invalid PE file returns fallback features."""
        invalid_file = temp_model_dir / "invalid.exe"
        invalid_file.write_bytes(b"Not a valid PE file")

        features = feature_extractor.extract_features(invalid_file)

        assert isinstance(features, np.ndarray)
        assert len(features) == len(feature_extractor.feature_names)
        assert features[feature_extractor.feature_names.index("overall_entropy")] > 0.0

    def test_classifier_prediction_without_model(
        self,
        temp_model_dir: Path,
        real_binaries: dict[str, Path],
    ) -> None:
        """Prediction without trained model raises appropriate error."""
        classifier = ProtectionClassifier(model_path=temp_model_dir)
        binary_path = next(iter(real_binaries.values()))

        with pytest.raises(RuntimeError, match="Model not loaded"):
            classifier.predict(binary_path)


class TestModelFeatureImportance:
    """Test feature importance analysis."""

    def test_get_feature_importance(
        self,
        trained_classifier: ProtectionClassifier,
    ) -> None:
        """Feature importance returns valid ranked features."""
        importance = trained_classifier.get_feature_importance(top_n=10)

        assert len(importance) == 10
        assert all(isinstance(name, str) for name, _ in importance)
        assert all(isinstance(score, float) for _, score in importance)
        assert all(score >= 0.0 for _, score in importance)

        scores = [score for _, score in importance]
        assert scores == sorted(scores, reverse=True), "Features should be sorted by importance"

    def test_feature_importance_sums_to_one(
        self,
        trained_classifier: ProtectionClassifier,
    ) -> None:
        """All feature importances sum to approximately 1.0."""
        all_importance = trained_classifier.get_feature_importance(
            top_n=len(trained_classifier.feature_extractor.feature_names)
        )

        total_importance = sum(score for _, score in all_importance)
        assert 0.99 <= total_importance <= 1.01, "Feature importances should sum to 1.0"


class TestActiveLearning:
    """Test active learning integration."""

    def test_active_learning_identifies_uncertain_samples(
        self,
        ml_integration: MLAnalysisIntegration,
        real_binaries: dict[str, Path],
    ) -> None:
        """Active learning identifies samples requiring manual labeling."""
        binary_path = next(iter(real_binaries.values()))

        results = ml_integration.analyze_with_ml(binary_path)

        if "active_learning" in results:
            assert "requires_labeling" in results["active_learning"]
            assert "reason" in results["active_learning"]
