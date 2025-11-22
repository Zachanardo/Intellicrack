"""Machine learning module for protection scheme classification.

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

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.incremental_learner import IncrementalLearner, TrainingSample
from intellicrack.core.ml.ml_integration import MLAnalysisIntegration
from intellicrack.core.ml.protection_classifier import ClassificationResult, ProtectionClassifier
from intellicrack.core.ml.sample_database import SampleDatabase, SampleMetadata


__all__ = [
    "BinaryFeatureExtractor",
    "ClassificationResult",
    "IncrementalLearner",
    "MLAnalysisIntegration",
    "ProtectionClassifier",
    "SampleDatabase",
    "SampleMetadata",
    "TrainingSample",
]
