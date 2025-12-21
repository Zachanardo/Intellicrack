"""Production tests for ML sample database.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import hashlib
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pytest

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.sample_database import SampleDatabase, SampleMetadata


class TestSampleDatabase:
    """Test sample database functionality."""

    @pytest.fixture
    def temp_db_path(self) -> Path:
        """Create temporary database directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir

        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_database(self, temp_db_path: Path) -> SampleDatabase:
        """Create sample database instance."""
        return SampleDatabase(database_path=temp_db_path)

    @pytest.fixture
    def test_binary(self) -> Path:
        """Create test binary file."""
        temp_file = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        temp_file.write_bytes(b"MZ\x90\x00" + b"TEST_BINARY_DATA" * 100)
        yield temp_file

        if temp_file.exists():
            temp_file.unlink()

    def test_database_initialization(self, sample_database: SampleDatabase, temp_db_path: Path) -> None:
        """Database initializes with correct directory structure."""
        assert sample_database.database_path == temp_db_path
        assert temp_db_path.exists()
        assert sample_database.index_file.parent == temp_db_path

    def test_add_sample_success(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database adds new sample successfully."""
        success, file_hash = sample_database.add_sample(
            binary_path=test_binary,
            protection_type="VMProtect",
            confidence=0.95,
            source="test",
            verified=True,
            notes="Test sample",
        )

        assert success is True
        assert len(file_hash) == 64
        assert file_hash in sample_database.index
        assert sample_database.index[file_hash].protection_type == "VMProtect"
        assert sample_database.index[file_hash].confidence == 0.95
        assert sample_database.index[file_hash].verified is True

    def test_add_sample_copies_file(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database copies sample file to organized directory."""
        success, file_hash = sample_database.add_sample(
            binary_path=test_binary,
            protection_type="Themida",
            copy_file=True,
        )

        assert success is True

        expected_dir = sample_database.database_path / "Themida"
        assert expected_dir.exists()

        copied_file = sample_database.get_sample_path(file_hash)
        assert copied_file is not None
        assert copied_file.exists()
        assert copied_file.parent == expected_dir

    def test_add_sample_without_copying(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database tracks sample without copying file."""
        success, file_hash = sample_database.add_sample(
            binary_path=test_binary,
            protection_type="Denuvo",
            copy_file=False,
        )

        assert success is True
        assert file_hash in sample_database.index

    def test_add_duplicate_sample_same_label(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database handles duplicate samples with same label."""
        success1, hash1 = sample_database.add_sample(test_binary, "VMProtect")
        success2, hash2 = sample_database.add_sample(test_binary, "VMProtect")

        assert success1 is True
        assert success2 is True
        assert hash1 == hash2

    def test_add_duplicate_sample_different_label_higher_confidence(
        self, sample_database: SampleDatabase, test_binary: Path
    ) -> None:
        """Database updates label when duplicate has higher confidence."""
        sample_database.add_sample(test_binary, "VMProtect", confidence=0.5)
        success, file_hash = sample_database.add_sample(test_binary, "Themida", confidence=0.95)

        assert success is True
        assert sample_database.index[file_hash].protection_type == "Themida"
        assert sample_database.index[file_hash].confidence == 0.95

    def test_add_duplicate_sample_different_label_lower_confidence(
        self, sample_database: SampleDatabase, test_binary: Path
    ) -> None:
        """Database keeps original label when duplicate has lower confidence."""
        sample_database.add_sample(test_binary, "VMProtect", confidence=0.95)
        success, file_hash = sample_database.add_sample(test_binary, "Themida", confidence=0.5)

        assert success is True
        assert sample_database.index[file_hash].protection_type == "VMProtect"
        assert sample_database.index[file_hash].confidence == 0.95

    def test_add_nonexistent_file(self, sample_database: SampleDatabase) -> None:
        """Database handles nonexistent file gracefully."""
        fake_path = Path("nonexistent_file.exe")

        success, message = sample_database.add_sample(fake_path, "VMProtect")

        assert success is False
        assert "not found" in message.lower()

    def test_get_sample_path(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database retrieves sample path by hash."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect")

        sample_path = sample_database.get_sample_path(file_hash)

        assert sample_path is not None
        assert sample_path.exists()
        assert file_hash in str(sample_path)

    def test_get_sample_path_nonexistent(self, sample_database: SampleDatabase) -> None:
        """Database returns None for nonexistent sample."""
        fake_hash = "a" * 64

        sample_path = sample_database.get_sample_path(fake_hash)

        assert sample_path is None

    def test_get_samples_by_protection(self, sample_database: SampleDatabase) -> None:
        """Database retrieves samples by protection type."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary1.write_bytes(b"MZ\x90\x00SAMPLE1" * 50)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(b"MZ\x90\x00SAMPLE2" * 50)

        binary3 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary3.write_bytes(b"MZ\x90\x00SAMPLE3" * 50)

        try:
            sample_database.add_sample(binary1, "VMProtect")
            sample_database.add_sample(binary2, "VMProtect")
            sample_database.add_sample(binary3, "Themida")

            vmprotect_samples = sample_database.get_samples_by_protection("VMProtect")

            assert len(vmprotect_samples) == 2
            assert all(metadata.protection_type == "VMProtect" for _, metadata in vmprotect_samples)

        finally:
            for binary in [binary1, binary2, binary3]:
                if binary.exists():
                    binary.unlink()

    def test_get_all_samples(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database retrieves all samples."""
        binary1 = test_binary
        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(b"MZ\x90\x00DIFFERENT" * 50)

        try:
            sample_database.add_sample(binary1, "VMProtect")
            sample_database.add_sample(binary2, "Themida")

            all_samples = sample_database.get_all_samples()

            assert len(all_samples) == 2

        finally:
            if binary2.exists():
                binary2.unlink()

    def test_get_statistics(self, sample_database: SampleDatabase) -> None:
        """Database generates accurate statistics."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary1.write_bytes(b"MZ\x90\x00" * 1000)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(b"MZ\x90\x00" * 2000)

        try:
            sample_database.add_sample(binary1, "VMProtect", confidence=0.8, source="auto", verified=True)
            sample_database.add_sample(binary2, "Themida", confidence=0.9, source="manual", verified=False)

            stats = sample_database.get_statistics()

            assert stats["total_samples"] == 2
            assert stats["protection_types"]["VMProtect"] == 1
            assert stats["protection_types"]["Themida"] == 1
            assert stats["verified_samples"] == 1
            assert stats["avg_confidence"] == pytest.approx(0.85)

        finally:
            for binary in [binary1, binary2]:
                if binary.exists():
                    binary.unlink()

    def test_verify_sample(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database updates sample verification status."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect", verified=False)

        result = sample_database.verify_sample(file_hash, verified=True)

        assert result is True
        assert sample_database.index[file_hash].verified is True

    def test_verify_nonexistent_sample(self, sample_database: SampleDatabase) -> None:
        """Database handles verification of nonexistent sample."""
        fake_hash = "a" * 64

        result = sample_database.verify_sample(fake_hash)

        assert result is False

    def test_update_sample_notes(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database updates sample notes."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect", notes="Original note")

        result = sample_database.update_sample_notes(file_hash, "Updated note")

        assert result is True
        assert sample_database.index[file_hash].notes == "Updated note"

    def test_update_notes_nonexistent_sample(self, sample_database: SampleDatabase) -> None:
        """Database handles note update for nonexistent sample."""
        fake_hash = "a" * 64

        result = sample_database.update_sample_notes(fake_hash, "Note")

        assert result is False

    def test_remove_sample_with_file_deletion(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database removes sample and deletes file."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect")

        sample_path = sample_database.get_sample_path(file_hash)
        assert sample_path is not None
        assert sample_path.exists()

        result = sample_database.remove_sample(file_hash, delete_file=True)

        assert result is True
        assert file_hash not in sample_database.index
        assert not sample_path.exists()

    def test_remove_sample_without_file_deletion(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database removes sample metadata but keeps file."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect")

        sample_path = sample_database.get_sample_path(file_hash)
        assert sample_path is not None

        result = sample_database.remove_sample(file_hash, delete_file=False)

        assert result is True
        assert file_hash not in sample_database.index
        assert sample_path.exists()

    def test_export_dataset(self, sample_database: SampleDatabase, temp_db_path: Path) -> None:
        """Database exports dataset with correct organization."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary1.write_bytes(b"MZ\x90\x00SAMPLE1" * 50)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(b"MZ\x90\x00SAMPLE2" * 50)

        try:
            sample_database.add_sample(binary1, "VMProtect", confidence=0.8)
            sample_database.add_sample(binary2, "Themida", confidence=0.9)

            export_dir = temp_db_path / "exported"

            export_counts = sample_database.export_dataset(
                output_dir=export_dir,
                min_confidence=0.7,
                verified_only=False,
            )

            assert export_counts["VMProtect"] == 1
            assert export_counts["Themida"] == 1
            assert (export_dir / "VMProtect").exists()
            assert (export_dir / "Themida").exists()

        finally:
            for binary in [binary1, binary2]:
                if binary.exists():
                    binary.unlink()

    def test_export_dataset_with_filters(self, sample_database: SampleDatabase, temp_db_path: Path) -> None:
        """Database exports dataset respecting filters."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary1.write_bytes(b"MZ\x90\x00LOW" * 50)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(b"MZ\x90\x00HIGH" * 50)

        try:
            sample_database.add_sample(binary1, "VMProtect", confidence=0.5, verified=False)
            sample_database.add_sample(binary2, "Themida", confidence=0.95, verified=True)

            export_dir = temp_db_path / "exported_filtered"

            export_counts = sample_database.export_dataset(
                output_dir=export_dir,
                min_confidence=0.8,
                verified_only=True,
            )

            assert export_counts.get("VMProtect", 0) == 0
            assert export_counts.get("Themida", 0) == 1

        finally:
            for binary in [binary1, binary2]:
                if binary.exists():
                    binary.unlink()

    def test_file_hash_calculation(self, sample_database: SampleDatabase, test_binary: Path) -> None:
        """Database calculates consistent file hashes."""
        hash1 = sample_database._calculate_file_hash(test_binary)
        hash2 = sample_database._calculate_file_hash(test_binary)

        assert hash1 == hash2
        assert len(hash1) == 64
        assert all(c in "0123456789abcdef" for c in hash1)

    def test_index_persistence(self, sample_database: SampleDatabase, test_binary: Path, temp_db_path: Path) -> None:
        """Database persists index to disk and reloads correctly."""
        success, file_hash = sample_database.add_sample(test_binary, "VMProtect", confidence=0.9)

        assert success is True

        new_db = SampleDatabase(database_path=temp_db_path)

        assert file_hash in new_db.index
        assert new_db.index[file_hash].protection_type == "VMProtect"
        assert new_db.index[file_hash].confidence == 0.9

    def test_corrupted_index_recovery(self, sample_database: SampleDatabase) -> None:
        """Database recovers from corrupted index file."""
        sample_database.index_file.write_text("CORRUPTED JSON{{{")

        sample_database._load_index()

        assert isinstance(sample_database.index, dict)
        assert len(sample_database.index) == 0

    def test_extract_training_data(self, sample_database: SampleDatabase) -> None:
        """Database extracts training data in correct format."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        pe_header += b"\x00" * 48
        pe_header += b"PE\x00\x00" + b"\x4C\x01\x02\x00"
        binary1.write_bytes(pe_header + b"\x00" * 2048)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(pe_header + b"\xFF" * 2048)

        try:
            sample_database.add_sample(binary1, "VMProtect", confidence=0.9)
            sample_database.add_sample(binary2, "Themida", confidence=0.85)

            extractor = BinaryFeatureExtractor()
            X, y = sample_database.extract_training_data(min_confidence=0.8)

            assert X.shape[0] == 2
            assert y.shape == (2,)
            assert set(y) == {"VMProtect", "Themida"}
            assert X.shape[1] > 0

        finally:
            for binary in [binary1, binary2]:
                if binary.exists():
                    binary.unlink()

    def test_extract_training_data_with_filters(self, sample_database: SampleDatabase) -> None:
        """Database filters samples when extracting training data."""
        binary1 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        pe_header += b"\x00" * 48
        pe_header += b"PE\x00\x00" + b"\x4C\x01\x02\x00"
        binary1.write_bytes(pe_header + b"\x00" * 2048)

        binary2 = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".exe").name)
        binary2.write_bytes(pe_header + b"\xFF" * 2048)

        try:
            sample_database.add_sample(binary1, "VMProtect", confidence=0.6, verified=False)
            sample_database.add_sample(binary2, "Themida", confidence=0.95, verified=True)

            extractor = BinaryFeatureExtractor()
            X, y = sample_database.extract_training_data(
                min_confidence=0.8,
                verified_only=True,
            )

            assert X.shape[0] == 1
            assert y.shape == (1,)
            assert y[0] == "Themida"
            assert X.shape[1] > 0

        finally:
            for binary in [binary1, binary2]:
                if binary.exists():
                    binary.unlink()
