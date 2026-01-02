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

        Sets up the ML classifier, optional incremental learning, and optional
        sample database for the binary analysis pipeline.

        Args:
            model_path: Optional path to a trained model file. If None, searches
                default locations for the model.
            enable_incremental_learning: Whether to enable incremental learning
                capabilities for continuous model improvement.
            enable_sample_database: Whether to initialize the sample database
                for tracking verified protection samples.

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
            self.logger.info("Sample database initialized at %s", self.sample_database.database_path)

    def classify_binary(
        self,
        binary_path: str | Path,
        include_alternatives: bool = True,
    ) -> dict[str, Any]:
        """Classify a binary using ML model.

        Performs ML-based classification of the binary to detect protection
        mechanisms and returns confidence scores along with alternative predictions
        if requested.

        Args:
            binary_path: Path to the binary file to classify.
            include_alternatives: If True, includes top alternative predictions
                in the results.

        Returns:
            Dictionary containing classification results with keys:
            - enabled: Whether ML classification is available
            - primary_protection: Detected protection type
            - confidence: Confidence score (0-1)
            - confidence_level: Categorical confidence level
            - model_version: Version of the trained model
            - reliable: Whether the prediction is reliable
            - alternatives: Top predictions (if include_alternatives=True)
            - warning: Low confidence warning message (if applicable)
            - error: Error message (if classification failed)

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
                classification["alternatives"] = [{"protection": prot, "confidence": conf} for prot, conf in result.top_predictions]

            if confidence_level == "low":
                classification["warning"] = "Low confidence prediction - manual verification recommended"

            return classification

        except Exception as e:
            self.logger.exception("Classification failed for %s: %s", binary_path, e)
            return {
                "enabled": True,
                "error": str(e),
            }

    def analyze_with_ml(self, binary_path: str | Path) -> dict[str, Any]:
        """Perform comprehensive ML-enhanced analysis.

        Runs full ML analysis on the binary, including classification,
        recommended tools, active learning queries, and sample database statistics.

        Args:
            binary_path: Path to the binary file to analyze.

        Returns:
            Dictionary containing complete analysis results with keys:
            - binary_path: Path to the analyzed binary
            - ml_enabled: Whether ML analysis is enabled
            - classification: Classification results (if ML enabled)
            - recommended_tools: Tools recommended for detected protection
            - active_learning: Active learning requirements (if applicable)
            - database_stats: Sample database statistics (if enabled)

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

        Adds a manually verified binary sample to both the sample database and
        incremental learner for model improvement.

        Args:
            binary_path: Path to the binary file to add.
            protection_type: The verified protection mechanism used by the binary.
            verified: Whether this sample has been manually verified.
            notes: Optional additional notes about the sample.

        Returns:
            True if the sample was successfully added to all enabled systems,
            False otherwise.

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

        Retrains the ML model using either samples from the database or the
        incremental learner buffer. Performs cross-validation and saves the
        updated model.

        Args:
            use_database: If True, uses samples from the sample database.
                If False, uses samples from incremental learner.
            min_confidence: Minimum confidence threshold for samples to be
                included in training data.
            n_estimators: Number of estimators for the random forest model.

        Returns:
            Dictionary containing training results with keys:
            - error: Error message (if training failed)
            - Training metrics and model performance data (if successful)

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
            Dictionary containing learning system statistics including model
            information, incremental learning buffer stats, and sample database
            statistics.

        """
        stats: dict[str, Any] = {
            "ml_enabled": self.enabled,
        }

        if self.enabled and self.classifier.model:
            stats["model_info"] = {
                "version": self.classifier.MODEL_VERSION,
                "n_features": len(self.classifier.feature_extractor.feature_names),
                "classes": self.classifier.label_encoder.classes_.tolist() if self.classifier.label_encoder else [],
            }

        if self.incremental_learner:
            stats["incremental_learning"] = self.incremental_learner.get_buffer_statistics()

        if self.sample_database:
            stats["sample_database"] = self.sample_database.get_statistics()

        return stats

    def _get_confidence_level(self, confidence: float) -> str:
        """Categorize confidence score.

        Args:
            confidence: Confidence score between 0 and 1.

        Returns:
            str: Confidence level string ("very_high", "high", "medium", "low", or
                "very_low") based on the confidence score thresholds.

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
            protection: Name of the protection scheme to get recommendations for.

        Returns:
            Dictionary with tool recommendations organized by category
            (unpackers, analyzers, techniques). Returns default recommendations
            for unknown protection types.

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
