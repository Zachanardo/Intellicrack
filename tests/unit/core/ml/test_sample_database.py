"""Tests for sample database management.

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

import struct

import numpy as np
import pytest

from intellicrack.core.ml.sample_database import SampleDatabase


class TestSampleDatabase:
    """Tests for sample database."""

    @pytest.fixture
    def database(self, tmp_path):
        """Create sample database instance."""
        return SampleDatabase(database_path=tmp_path / "sample_db")

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create test binary file."""
        binary_file = tmp_path / "test_sample.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000
        pe_data += b'VMProtect' * 50

        with open(binary_file, 'wb') as f:
            f.write(pe_data)

        return binary_file

    def test_database_initialization(self, database):
        """Test database initialization."""
        assert database.database_path.exists()
        assert database.index == {}

    def test_add_sample(self, database, test_binary):
        """Test adding a sample to database."""
        success, file_hash = database.add_sample(
            binary_path=test_binary,
            protection_type='VMProtect',
            confidence=0.9,
            source='manual',
            verified=True,
            notes='Test sample'
        )

        assert success
        assert file_hash in database.index

        metadata = database.index[file_hash]
        assert metadata.protection_type == 'VMProtect'
        assert metadata.confidence == 0.9
        assert metadata.verified

    def test_add_duplicate_sample(self, database, test_binary):
        """Test adding duplicate sample."""
        success1, hash1 = database.add_sample(test_binary, 'VMProtect', confidence=0.8)
        success2, hash2 = database.add_sample(test_binary, 'VMProtect', confidence=0.9)

        assert success1 and success2
        assert hash1 == hash2
        assert len(database.index) == 1

    def test_add_duplicate_with_different_label(self, database, test_binary):
        """Test adding duplicate with different protection label."""
        success1, hash1 = database.add_sample(test_binary, 'VMProtect', confidence=0.7)
        success2, hash2 = database.add_sample(test_binary, 'Themida', confidence=0.9)

        assert success1 and success2
        assert hash1 == hash2

        metadata = database.index[hash1]
        assert metadata.protection_type == 'Themida'
        assert metadata.confidence == 0.9

    def test_get_sample_path(self, database, test_binary):
        """Test retrieving sample path by hash."""
        success, file_hash = database.add_sample(test_binary, 'VMProtect')

        assert success

        sample_path = database.get_sample_path(file_hash)
        assert sample_path is not None
        assert sample_path.exists()

    def test_get_samples_by_protection(self, database, tmp_path):
        """Test retrieving samples by protection type."""
        for i in range(5):
            binary_file = tmp_path / f"vmp_{i}.exe"
            binary_file.write_bytes(b'MZ' + b'\x00' * 100 + bytes([i]))
            database.add_sample(binary_file, 'VMProtect')

        for i in range(3):
            binary_file = tmp_path / f"themida_{i}.exe"
            binary_file.write_bytes(b'MZ' + b'\x00' * 100 + bytes([i + 10]))
            database.add_sample(binary_file, 'Themida')

        vmp_samples = database.get_samples_by_protection('VMProtect')
        themida_samples = database.get_samples_by_protection('Themida')

        assert len(vmp_samples) == 5
        assert len(themida_samples) == 3

    def test_get_all_samples(self, database, tmp_path):
        """Test retrieving all samples."""
        for i in range(10):
            binary_file = tmp_path / f"sample_{i}.exe"
            binary_file.write_bytes(b'MZ' + b'\x00' * 100 + bytes([i]))
            protection = 'VMProtect' if i % 2 == 0 else 'Themida'
            database.add_sample(binary_file, protection)

        all_samples = database.get_all_samples()
        assert len(all_samples) == 10

    def test_extract_training_data(self, database, tmp_path):
        """Test extracting training data."""
        for i in range(20):
            binary_file = tmp_path / f"train_{i}.exe"

            dos_header = bytearray(64)
            dos_header[0:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            protection = ['VMProtect', 'Themida', 'UPX'][i % 3]
            confidence = 0.9 if i < 15 else 0.4

            database.add_sample(binary_file, protection, confidence=confidence)

        X, y = database.extract_training_data(min_confidence=0.7)

        assert len(X) == 15
        assert len(y) == 15

    def test_get_statistics(self, database, tmp_path):
        """Test database statistics."""
        for i in range(15):
            binary_file = tmp_path / f"stat_{i}.exe"
            binary_file.write_bytes(b'MZ' + b'\x00' * 100 + bytes([i]))

            protection = 'VMProtect' if i < 10 else 'Themida'
            verified = i % 3 == 0

            database.add_sample(
                binary_file,
                protection,
                confidence=0.8,
                verified=verified
            )

        stats = database.get_statistics()

        assert stats['total_samples'] == 15
        assert stats['protection_types']['VMProtect'] == 10
        assert stats['protection_types']['Themida'] == 5
        assert stats['verified_samples'] == 5
        assert stats['avg_confidence'] == 0.8

    def test_verify_sample(self, database, test_binary):
        """Test marking sample as verified."""
        success, file_hash = database.add_sample(
            test_binary,
            'VMProtect',
            verified=False
        )

        assert success
        assert not database.index[file_hash].verified

        database.verify_sample(file_hash, verified=True)
        assert database.index[file_hash].verified

    def test_update_sample_notes(self, database, test_binary):
        """Test updating sample notes."""
        success, file_hash = database.add_sample(test_binary, 'VMProtect')

        assert success

        database.update_sample_notes(file_hash, "Updated notes")
        assert database.index[file_hash].notes == "Updated notes"

    def test_remove_sample(self, database, test_binary):
        """Test removing a sample."""
        success, file_hash = database.add_sample(test_binary, 'VMProtect')

        assert success
        assert file_hash in database.index

        database.remove_sample(file_hash, delete_file=True)
        assert file_hash not in database.index

    def test_export_dataset(self, database, tmp_path):
        """Test exporting dataset."""
        for i in range(20):
            binary_file = tmp_path / f"export_{i}.exe"
            binary_file.write_bytes(b'MZ' + b'\x00' * 100 + bytes([i]))

            protection = ['VMProtect', 'Themida', 'UPX'][i % 3]
            confidence = 0.9 if i < 15 else 0.5

            database.add_sample(binary_file, protection, confidence=confidence)

        export_dir = tmp_path / "exported_dataset"
        export_counts = database.export_dataset(
            output_dir=export_dir,
            min_confidence=0.7
        )

        assert export_dir.exists()
        assert sum(export_counts.values()) == 15

    def test_database_persistence(self, database, test_binary, tmp_path):
        """Test that database index persists across instances."""
        success, file_hash = database.add_sample(test_binary, 'VMProtect')

        assert success

        new_database = SampleDatabase(database_path=database.database_path)

        assert file_hash in new_database.index
        assert new_database.index[file_hash].protection_type == 'VMProtect'

    def test_file_hash_calculation(self, database, tmp_path):
        """Test file hash calculation consistency."""
        binary_file = tmp_path / "hash_test.exe"
        binary_file.write_bytes(b'MZ' + b'\x00' * 100 + b'test content')

        hash1 = database._calculate_file_hash(binary_file)
        hash2 = database._calculate_file_hash(binary_file)

        assert hash1 == hash2
        assert len(hash1) == 64
