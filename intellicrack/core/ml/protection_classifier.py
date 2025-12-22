"""ML-based protection scheme classifier for Intellicrack.

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
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor


@dataclass
class ClassificationResult:
    """Result of protection classification."""

    primary_protection: str
    confidence: float
    top_predictions: list[tuple[str, float]]
    feature_vector: NDArray[np.floating[Any]]
    model_version: str


class ProtectionClassifier:
    """Machine learning classifier for software protection schemes."""

    PROTECTION_SCHEMES = [
        "VMProtect",
        "Themida",
        "Enigma",
        "Obsidium",
        "ASProtect",
        "Armadillo",
        "Arxan",
        "UPX",
        "None",
    ]

    MODEL_VERSION = "1.0.0"

    def __init__(self, model_path: Path | None = None) -> None:
        """Initialize the protection classifier.

        Args:
            model_path: Path to pre-trained model directory. If None, will use default.

        """
        self.logger = logging.getLogger(__name__)
        self.feature_extractor = BinaryFeatureExtractor()

        if model_path is None:
            model_path = Path(__file__).parent.parent.parent / "models" / "protection_classifier"

        self.model_path = Path(model_path)
        self.model_file = self.model_path / "model.pkl"
        self.scaler_file = self.model_path / "scaler.pkl"
        self.encoder_file = self.model_path / "encoder.pkl"
        self.metadata_file = self.model_path / "metadata.json"

        self.model: RandomForestClassifier | None = None
        self.scaler: StandardScaler | None = None
        self.label_encoder: LabelEncoder | None = None
        self.metadata: dict[str, Any] = {}

        if self.model_file.exists():
            self.load_model()

    def train(
        self,
        X: NDArray[np.float64],
        y: NDArray[np.object_],
        test_size: float = 0.2,
        n_estimators: int = 200,
        random_state: int = 42,
        cross_validate: bool = True,
    ) -> dict[str, Any]:
        """Train the protection classifier.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels array (n_samples,)
            test_size: Proportion of dataset for testing
            n_estimators: Number of trees in random forest
            random_state: Random seed for reproducibility
            cross_validate: Whether to perform cross-validation

        Returns:
            Dictionary containing training metrics and results

        """
        self.logger.info("Starting model training with %d samples", len(X))

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled,
            y_encoded,
            test_size=test_size,
            random_state=random_state,
            stratify=y_encoded,
        )

        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features="sqrt",
            random_state=random_state,
            n_jobs=-1,
            class_weight="balanced",
        )

        self.logger.info("Training Random Forest with %d estimators", n_estimators)
        self.model.fit(X_train, y_train)

        y_train_pred = self.model.predict(X_train)
        train_accuracy = accuracy_score(y_train, y_train_pred)

        y_test_pred = self.model.predict(X_test)
        test_accuracy = accuracy_score(y_test, y_test_pred)

        self.logger.info("Train accuracy: %.4f", train_accuracy)
        self.logger.info("Test accuracy: %.4f", test_accuracy)

        results = {
            "train_accuracy": float(train_accuracy),
            "test_accuracy": float(test_accuracy),
            "n_samples": len(X),
            "n_features": X.shape[1],
            "n_classes": len(self.label_encoder.classes_),
            "model_version": self.MODEL_VERSION,
        }

        if cross_validate:
            self.logger.info("Performing 5-fold cross-validation")
            cv_scores = cross_val_score(
                self.model,
                X_scaled,
                y_encoded,
                cv=5,
                scoring="accuracy",
                n_jobs=-1,
            )
            results["cv_mean_accuracy"] = float(cv_scores.mean())
            results["cv_std_accuracy"] = float(cv_scores.std())
            self.logger.info(
                "Cross-validation accuracy: %.4f (+/- %.4f)",
                cv_scores.mean(),
                cv_scores.std() * 2,
            )

        class_names = self.label_encoder.classes_.tolist()
        conf_matrix = confusion_matrix(y_test, y_test_pred)
        class_report = classification_report(
            y_test,
            y_test_pred,
            target_names=class_names,
            output_dict=True,
        )

        results["confusion_matrix"] = conf_matrix.tolist()
        results["classification_report"] = class_report
        results["class_names"] = class_names

        feature_importance = self.model.feature_importances_
        feature_names = self.feature_extractor.feature_names
        top_features_idx = np.argsort(feature_importance)[-20:][::-1]
        top_features = [(feature_names[i], float(feature_importance[i])) for i in top_features_idx]
        results["top_features"] = top_features

        self.logger.info("Top 5 important features:")
        for feat_name, importance in top_features[:5]:
            self.logger.info("  %s: %.4f", feat_name, importance)

        return results

    def predict(self, binary_path: str | Path) -> ClassificationResult:
        """Predict protection scheme for a binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            ClassificationResult with prediction details

        Raises:
            RuntimeError: If model is not loaded
            ValueError: If feature extraction fails

        """
        if self.model is None or self.scaler is None or self.label_encoder is None:
            raise RuntimeError("Model not loaded. Train a model or load a pre-trained one.")

        feature_vector = self.feature_extractor.extract_features(binary_path)

        feature_vector_scaled = self.scaler.transform(feature_vector.reshape(1, -1))

        probabilities = self.model.predict_proba(feature_vector_scaled)[0]

        predicted_class_idx = np.argmax(probabilities)
        predicted_class = self.label_encoder.classes_[predicted_class_idx]
        confidence = float(probabilities[predicted_class_idx])

        top_indices = np.argsort(probabilities)[-3:][::-1]
        top_predictions = [(self.label_encoder.classes_[idx], float(probabilities[idx])) for idx in top_indices]

        self.logger.info(
            "Predicted protection: %s (confidence: %.4f)",
            predicted_class,
            confidence,
        )

        return ClassificationResult(
            primary_protection=predicted_class,
            confidence=confidence,
            top_predictions=top_predictions,
            feature_vector=feature_vector,
            model_version=self.MODEL_VERSION,
        )

    def save_model(self, output_path: Path | None = None) -> None:
        """Save trained model to disk.

        Args:
            output_path: Directory to save model files. Uses default if None.

        Raises:
            RuntimeError: If model is not trained

        """
        if self.model is None or self.scaler is None or self.label_encoder is None:
            raise RuntimeError("No model to save. Train a model first.")

        if output_path is not None:
            self.model_path = Path(output_path)
            self.model_file = self.model_path / "model.pkl"
            self.scaler_file = self.model_path / "scaler.pkl"
            self.encoder_file = self.model_path / "encoder.pkl"
            self.metadata_file = self.model_path / "metadata.json"

        self.model_path.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.model, self.model_file)
        joblib.dump(self.scaler, self.scaler_file)
        joblib.dump(self.label_encoder, self.encoder_file)

        self.metadata = {
            "model_version": self.MODEL_VERSION,
            "n_features": len(self.feature_extractor.feature_names),
            "feature_names": self.feature_extractor.feature_names,
            "classes": self.label_encoder.classes_.tolist(),
        }

        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        self.logger.info("Model saved to %s", self.model_path)

    def load_model(self, model_path: Path | None = None) -> None:
        """Load pre-trained model from disk.

        Args:
            model_path: Directory containing model files. Uses default if None.

        Raises:
            FileNotFoundError: If model files don't exist

        """
        if model_path is not None:
            self.model_path = Path(model_path)
            self.model_file = self.model_path / "model.pkl"
            self.scaler_file = self.model_path / "scaler.pkl"
            self.encoder_file = self.model_path / "encoder.pkl"
            self.metadata_file = self.model_path / "metadata.json"

        if not self.model_file.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_file}")

        self.model = joblib.load(self.model_file)
        self.scaler = joblib.load(self.scaler_file)
        self.label_encoder = joblib.load(self.encoder_file)

        if self.metadata_file.exists():
            with open(self.metadata_file, encoding="utf-8") as f:
                self.metadata = json.load(f)

        self.logger.info("Model loaded from %s", self.model_path)
        self.logger.info("Model version: %s", self.metadata.get("model_version", "unknown"))

    def get_feature_importance(self, top_n: int = 20) -> list[tuple[str, float]]:
        """Get top N most important features.

        Args:
            top_n: Number of top features to return

        Returns:
            List of (feature_name, importance) tuples

        Raises:
            RuntimeError: If model is not trained

        """
        if self.model is None:
            raise RuntimeError("Model not loaded")

        feature_importance = self.model.feature_importances_
        feature_names = self.feature_extractor.feature_names
        top_features_idx = np.argsort(feature_importance)[-top_n:][::-1]

        return [(feature_names[i], float(feature_importance[i])) for i in top_features_idx]
