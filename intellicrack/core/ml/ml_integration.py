"""Integration layer for ML classifier with binary analysis pipeline.

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

import logging
from pathlib import Path
from typing import Any

from intellicrack.core.ml.incremental_learner import IncrementalLearner
from intellicrack.core.ml.protection_classifier import ProtectionClassifier
from intellicrack.core.ml.sample_database import SampleDatabase


class MLAnalysisIntegration:
    """Integrates ML-based protection classification with binary analysis.

    This class provides seamless integration of the ML classifier into
    the Intellicrack analysis pipeline, including automatic classification,
    confidence assessment, and incremental learning capabilities.
    """

    HIGH_CONFIDENCE_THRESHOLD = 0.75
    MEDIUM_CONFIDENCE_THRESHOLD = 0.50
    LOW_CONFIDENCE_THRESHOLD = 0.25

    def __init__(
        self,
        model_path: Path | None = None,
        enable_incremental_learning: bool = True,
        enable_sample_database: bool = True,
    ) -> None:
        """Initialize ML analysis integration.

        Args:
            model_path: Path to trained model
            enable_incremental_learning: Enable incremental learning
            enable_sample_database: Enable sample database

        """
        self.logger = logging.getLogger(__name__)

        self.classifier = ProtectionClassifier(model_path=model_path)

        if not self.classifier.model_file.exists():
            self.logger.warning(
                "No trained model found at %s. ML classification disabled.",
                self.classifier.model_file,
            )
            self.enabled = False
        else:
            self.enabled = True
            self.logger.info("ML classifier loaded from %s", self.classifier.model_path)

        self.incremental_learner: IncrementalLearner | None = None
        if enable_incremental_learning and self.enabled:
            self.incremental_learner = IncrementalLearner(
                classifier=self.classifier,
                auto_retrain=True,
            )
            self.logger.info("Incremental learning enabled")

        self.sample_database: SampleDatabase | None = None
        if enable_sample_database:
            self.sample_database = SampleDatabase()
            self.logger.info(
                "Sample database initialized at %s", self.sample_database.database_path
            )

    def classify_binary(
        self,
        binary_path: str | Path,
        include_alternatives: bool = True,
    ) -> dict[str, Any]:
        """Classify a binary using ML model.

        Args:
            binary_path: Path to binary file
            include_alternatives: Include alternative predictions

        Returns:
            Classification results dictionary

        """
        if not self.enabled:
            return {
                "enabled": False,
                "error": "ML classifier not available",
            }

        try:
            result = self.classifier.predict(binary_path)

            confidence_level = self._get_confidence_level(result.confidence)

            classification = {
                "enabled": True,
                "primary_protection": result.primary_protection,
                "confidence": result.confidence,
                "confidence_level": confidence_level,
                "model_version": result.model_version,
                "reliable": confidence_level in ["high", "very_high"],
            }

            if include_alternatives:
                classification["alternatives"] = [
                    {"protection": prot, "confidence": conf}
                    for prot, conf in result.top_predictions
                ]

            if confidence_level == "low":
                classification["warning"] = (
                    "Low confidence prediction - manual verification recommended"
                )

            return classification

        except Exception as e:
            self.logger.error("Classification failed for %s: %s", binary_path, e)
            return {
                "enabled": True,
                "error": str(e),
            }

    def analyze_with_ml(self, binary_path: str | Path) -> dict[str, Any]:
        """Perform comprehensive ML-enhanced analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            Complete analysis results

        """
        binary_path = Path(binary_path)

        results = {
            "binary_path": str(binary_path),
            "ml_enabled": self.enabled,
        }

        if not self.enabled:
            return results

        classification = self.classify_binary(binary_path)
        results["classification"] = classification

        if classification.get("reliable"):
            results["recommended_tools"] = self._get_recommended_tools(
                classification["primary_protection"],
            )

        if self.incremental_learner:
            uncertain = self.incremental_learner.get_uncertain_predictions(
                min_uncertainty=0.4,
                max_count=5,
            )

            if any(str(path) == str(binary_path) for path, _ in uncertain):
                results["active_learning"] = {
                    "requires_labeling": True,
                    "reason": "Model is uncertain about this sample",
                }

        if self.sample_database:
            db_stats = self.sample_database.get_statistics()
            results["database_stats"] = db_stats

        return results

    def add_verified_sample(
        self,
        binary_path: Path,
        protection_type: str,
        verified: bool = True,
        notes: str = "",
    ) -> bool:
        """Add a verified sample to the learning system.

        Args:
            binary_path: Path to binary file
            protection_type: Verified protection type
            verified: Whether this is a verified sample
            notes: Additional notes

        Returns:
            True if successful

        """
        success = True

        if self.sample_database:
            db_success, file_hash = self.sample_database.add_sample(
                binary_path=binary_path,
                protection_type=protection_type,
                confidence=1.0,
                source="manual",
                verified=verified,
                notes=notes,
            )

            if not db_success:
                self.logger.error("Failed to add sample to database: %s", file_hash)
                success = False

        if self.incremental_learner:
            learner_success = self.incremental_learner.add_sample(
                binary_path=binary_path,
                protection_type=protection_type,
                confidence=1.0,
                source="manual",
                metadata={"verified": verified, "notes": notes},
            )

            if not learner_success:
                self.logger.error("Failed to add sample to incremental learner")
                success = False

        if success:
            self.logger.info(
                "Added verified sample: %s (%s)",
                binary_path.name,
                protection_type,
            )

        return success

    def retrain_model(
        self,
        use_database: bool = True,
        min_confidence: float = 0.7,
        n_estimators: int = 200,
    ) -> dict[str, Any]:
        """Retrain model with new samples.

        Args:
            use_database: Use samples from database
            min_confidence: Minimum confidence for training
            n_estimators: Number of estimators

        Returns:
            Training results

        """
        if not self.enabled:
            return {"error": "ML classifier not available"}

        if use_database and self.sample_database:
            self.logger.info("Retraining from sample database")

            X, y = self.sample_database.extract_training_data(
                min_confidence=min_confidence,
            )

            if len(X) < 50:
                return {
                    "error": f"Insufficient samples ({len(X)}) for training",
                    "minimum_required": 50,
                }

            results = self.classifier.train(
                X=X,
                y=y,
                n_estimators=n_estimators,
                cross_validate=True,
            )

            self.classifier.save_model()
            self.logger.info("Model retrained and saved")

            return results

        if self.incremental_learner:
            self.logger.info("Retraining from incremental learner buffer")
            return self.incremental_learner.retrain_incremental(
                n_estimators=n_estimators,
            )

        return {"error": "No training data available"}

    def get_learning_statistics(self) -> dict[str, Any]:
        """Get statistics about the learning system.

        Returns:
            Statistics dictionary

        """
        stats: dict[str, Any] = {
            "ml_enabled": self.enabled,
        }

        if self.enabled and self.classifier.model:
            stats["model_info"] = {
                "version": self.classifier.MODEL_VERSION,
                "n_features": len(self.classifier.feature_extractor.feature_names),
                "classes": self.classifier.label_encoder.classes_.tolist()
                if self.classifier.label_encoder
                else [],
            }

        if self.incremental_learner:
            stats["incremental_learning"] = self.incremental_learner.get_buffer_statistics()

        if self.sample_database:
            stats["sample_database"] = self.sample_database.get_statistics()

        return stats

    def _get_confidence_level(self, confidence: float) -> str:
        """Categorize confidence score.

        Args:
            confidence: Confidence score (0-1)

        Returns:
            Confidence level string

        """
        if confidence >= 0.90:
            return "very_high"
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            return "high"
        if confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
            return "medium"
        return "low" if confidence >= self.LOW_CONFIDENCE_THRESHOLD else "very_low"

    def _get_recommended_tools(self, protection: str) -> dict[str, list[str]]:
        """Get recommended tools for a protection scheme.

        Args:
            protection: Protection scheme name

        Returns:
            Dictionary of recommended tools by category

        """
        tool_recommendations = {
            "VMProtect": {
                "unpackers": ["VMProtect Unpacker", "Scylla Dumper"],
                "analyzers": ["Ghidra", "IDA Pro with VMP plugin"],
                "techniques": ["ESIL emulation", "Control flow deobfuscation"],
            },
            "Themida": {
                "unpackers": ["Themida Unpacker", "Manual OEP finder"],
                "analyzers": ["x64dbg", "Ghidra"],
                "techniques": ["Anti-debug bypass", "VM detection bypass"],
            },
            "Enigma": {
                "unpackers": ["Enigma Unpacker"],
                "analyzers": ["Ghidra", "x64dbg"],
                "techniques": ["Resource extraction", "License check removal"],
            },
            "UPX": {
                "unpackers": ["UPX -d", "Generic PE unpacker"],
                "analyzers": ["Any disassembler"],
                "techniques": ["Standard unpacking"],
            },
        }

        return tool_recommendations.get(
            protection,
            {
                "analyzers": ["Ghidra", "radare2"],
                "techniques": ["Standard analysis"],
            },
        )
