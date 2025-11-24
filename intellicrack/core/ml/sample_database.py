"""Sample database for managing training data and model updates.

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

import hashlib
import json
import logging
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor


@dataclass
class SampleMetadata:
    """Metadata for a training sample."""

    file_hash: str
    protection_type: str
    file_size: int
    timestamp: str
    confidence: float
    source: str
    verified: bool = False
    notes: str = ""
    feature_extraction_version: str = "1.0.0"


class SampleDatabase:
    """Manages organized storage of training samples with metadata.

    This class provides structured storage for binary samples used in
    training the protection classifier, including automatic organization,
    deduplication, and metadata tracking.
    """

    def __init__(self, database_path: Path | None = None) -> None:
        """Initialize sample database.

        Args:
            database_path: Root directory for sample database

        """
        self.logger = logging.getLogger(__name__)

        if database_path is None:
            database_path = Path(__file__).parent.parent.parent / "data" / "training_samples"

        self.database_path = Path(database_path)
        self.database_path.mkdir(parents=True, exist_ok=True)

        self.index_file = self.database_path / "index.json"
        self.index: dict[str, SampleMetadata] = {}

        self._load_index()

    def add_sample(
        self,
        binary_path: Path,
        protection_type: str,
        confidence: float = 1.0,
        source: str = "manual",
        verified: bool = False,
        notes: str = "",
        copy_file: bool = True,
    ) -> tuple[bool, str]:
        """Add a sample to the database.

        Args:
            binary_path: Path to the binary file
            protection_type: Protection scheme label
            confidence: Confidence in the label
            source: Source of the sample
            verified: Whether the label has been verified
            notes: Additional notes
            copy_file: Whether to copy file into database

        Returns:
            Tuple of (success, file_hash or error_message)

        """
        if not binary_path.exists():
            return False, f"File not found: {binary_path}"

        try:
            file_hash = self._calculate_file_hash(binary_path)

            if file_hash in self.index:
                existing = self.index[file_hash]
                if existing.protection_type == protection_type:
                    self.logger.info("Sample %s already in database", file_hash[:16])
                    return True, file_hash

                self.logger.warning(
                    "Duplicate file with different label: %s vs %s",
                    existing.protection_type,
                    protection_type,
                )

                if confidence > existing.confidence:
                    self.logger.info("Updating sample with higher confidence label")
                    self.index[file_hash].protection_type = protection_type
                    self.index[file_hash].confidence = confidence
                    self.index[file_hash].verified = verified
                    self._save_index()

                return True, file_hash

            file_size = binary_path.stat().st_size

            metadata = SampleMetadata(
                file_hash=file_hash,
                protection_type=protection_type,
                file_size=file_size,
                timestamp=datetime.now(UTC).isoformat(),
                confidence=confidence,
                source=source,
                verified=verified,
                notes=notes,
            )

            if copy_file:
                dest_dir = self.database_path / protection_type
                dest_dir.mkdir(parents=True, exist_ok=True)

                dest_file = dest_dir / f"{file_hash}{binary_path.suffix}"

                if not dest_file.exists():
                    shutil.copy2(binary_path, dest_file)
                    self.logger.info("Copied sample to %s", dest_file)

            self.index[file_hash] = metadata
            self._save_index()

            self.logger.info(
                "Added sample %s (%s, confidence: %.2f)",
                file_hash[:16],
                protection_type,
                confidence,
            )

            return True, file_hash

        except Exception as e:
            self.logger.error("Failed to add sample: %s", e)
            return False, str(e)

    def get_sample_path(self, file_hash: str) -> Path | None:
        """Get the file path for a sample by hash.

        Args:
            file_hash: Hash of the sample

        Returns:
            Path to the sample file or None if not found

        """
        if file_hash not in self.index:
            return None

        metadata = self.index[file_hash]
        sample_dir = self.database_path / metadata.protection_type

        return next((file for file in sample_dir.iterdir() if file.stem == file_hash), None)

    def get_samples_by_protection(self, protection_type: str) -> list[tuple[Path, SampleMetadata]]:
        """Get all samples for a specific protection type.

        Args:
            protection_type: Protection scheme name

        Returns:
            List of (path, metadata) tuples

        """
        samples = []

        for file_hash, metadata in self.index.items():
            if metadata.protection_type == protection_type:
                if sample_path := self.get_sample_path(file_hash):
                    samples.append((sample_path, metadata))

        return samples

    def get_all_samples(self) -> list[tuple[Path, SampleMetadata]]:
        """Get all samples in the database.

        Returns:
            List of (path, metadata) tuples

        """
        samples = []

        for file_hash in self.index:
            if sample_path := self.get_sample_path(file_hash):
                samples.append((sample_path, self.index[file_hash]))

        return samples

    def extract_training_data(
        self,
        min_confidence: float = 0.5,
        verified_only: bool = False,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Extract feature vectors and labels for training.

        Args:
            min_confidence: Minimum confidence threshold
            min_confidence: Minimum confidence threshold
            verified_only: Only include verified samples

        Returns:
            Tuple of (features, labels) arrays

        """
        extractor = BinaryFeatureExtractor()
        features_list = []
        labels_list = []

        for file_hash, metadata in self.index.items():
            if metadata.confidence < min_confidence:
                continue

            if verified_only and not metadata.verified:
                continue

            sample_path = self.get_sample_path(file_hash)
            if not sample_path or not sample_path.exists():
                self.logger.warning("Sample file missing: %s", file_hash[:16])
                continue

            try:
                feature_vector = extractor.extract_features(sample_path)
                features_list.append(feature_vector)
                labels_list.append(metadata.protection_type)

            except Exception as e:
                self.logger.error("Failed to extract features from %s: %s", sample_path.name, e)
                continue

        if not features_list:
            self.logger.warning("No samples met the criteria")
            return np.array([]), np.array([])

        X = np.vstack(features_list)
        y = np.array(labels_list)

        self.logger.info("Extracted features from %d samples", len(X))

        return X, y

    def get_statistics(self) -> dict[str, Any]:
        """Get database statistics.

        Returns:
            Statistics dictionary

        """
        if not self.index:
            return {"total_samples": 0}

        protection_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        verified_count = 0
        total_size = 0
        confidence_values: list[float] = []

        for metadata in self.index.values():
            protection_counts[metadata.protection_type] = (
                protection_counts.get(
                    metadata.protection_type,
                    0,
                )
                + 1
            )
            source_counts[metadata.source] = source_counts.get(metadata.source, 0) + 1

            if metadata.verified:
                verified_count += 1

            total_size += metadata.file_size
            confidence_values.append(metadata.confidence)

        return {
            "total_samples": len(self.index),
            "protection_types": protection_counts,
            "sources": source_counts,
            "verified_samples": verified_count,
            "total_size_mb": total_size / (1024 * 1024),
            "avg_confidence": float(np.mean(confidence_values)) if confidence_values else 0.0,
            "min_confidence": float(np.min(confidence_values)) if confidence_values else 0.0,
            "max_confidence": float(np.max(confidence_values)) if confidence_values else 0.0,
        }

    def verify_sample(self, file_hash: str, verified: bool = True) -> bool:
        """Mark a sample as verified.

        Args:
            file_hash: Hash of the sample
            verified: Verification status

        Returns:
            True if successful

        """
        if file_hash not in self.index:
            return False

        self.index[file_hash].verified = verified
        self._save_index()

        self.logger.info("Sample %s verification status: %s", file_hash[:16], verified)
        return True

    def update_sample_notes(self, file_hash: str, notes: str) -> bool:
        """Update notes for a sample.

        Args:
            file_hash: Hash of the sample
            notes: New notes

        Returns:
            True if successful

        """
        if file_hash not in self.index:
            return False

        self.index[file_hash].notes = notes
        self._save_index()

        return True

    def remove_sample(self, file_hash: str, delete_file: bool = True) -> bool:
        """Remove a sample from the database.

        Args:
            file_hash: Hash of the sample
            delete_file: Whether to delete the actual file

        Returns:
            True if successful

        """
        if file_hash not in self.index:
            return False

        if delete_file:
            sample_path = self.get_sample_path(file_hash)
            if sample_path and sample_path.exists():
                try:
                    sample_path.unlink()
                    self.logger.info("Deleted sample file: %s", sample_path)
                except Exception as e:
                    self.logger.error("Failed to delete sample file: %s", e)

        del self.index[file_hash]
        self._save_index()

        self.logger.info("Removed sample %s from database", file_hash[:16])
        return True

    def export_dataset(
        self,
        output_dir: Path,
        min_confidence: float = 0.7,
        verified_only: bool = False,
    ) -> dict[str, int]:
        """Export dataset in organized directory structure.

        Args:
            output_dir: Output directory
            min_confidence: Minimum confidence threshold
            verified_only: Only export verified samples

        Returns:
            Dictionary with export statistics

        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        export_counts: dict[str, int] = {}

        for file_hash, metadata in self.index.items():
            if metadata.confidence < min_confidence:
                continue

            if verified_only and not metadata.verified:
                continue

            sample_path = self.get_sample_path(file_hash)
            if not sample_path or not sample_path.exists():
                continue

            dest_dir = output_dir / metadata.protection_type
            dest_dir.mkdir(parents=True, exist_ok=True)

            dest_file = dest_dir / sample_path.name

            try:
                shutil.copy2(sample_path, dest_file)
                export_counts[metadata.protection_type] = (
                    export_counts.get(
                        metadata.protection_type,
                        0,
                    )
                    + 1
                )
            except Exception as e:
                self.logger.error("Failed to copy %s: %s", sample_path, e)

        self.logger.info("Exported %d samples to %s", sum(export_counts.values()), output_dir)

        return export_counts

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file.

        Args:
            file_path: Path to file

        Returns:
            Hex digest of file hash

        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _load_index(self) -> None:
        """Load database index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file, encoding="utf-8") as f:
                    data = json.load(f)

                self.index = {file_hash: SampleMetadata(**metadata) for file_hash, metadata in data.items()}

                self.logger.info("Loaded index with %d samples", len(self.index))

            except Exception as e:
                self.logger.error("Failed to load index: %s", e)
                self.index = {}

    def _save_index(self) -> None:
        """Save database index to disk."""
        try:
            data = {file_hash: asdict(metadata) for file_hash, metadata in self.index.items()}

            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            self.logger.error("Failed to save index: %s", e)
