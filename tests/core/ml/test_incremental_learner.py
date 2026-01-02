"""Tests for incremental learning system.

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

from typing import Any
import struct

import numpy as np
import pytest

from intellicrack.core.ml.incremental_learner import IncrementalLearner
from intellicrack.core.ml.protection_classifier import ProtectionClassifier


class TestIncrementalLearner:
    """Tests for incremental learning system."""

    @pytest.fixture
    def classifier(self, tmp_path) -> Any:
        """Create trained classifier for testing."""
        classifier = ProtectionClassifier(model_path=tmp_path / "test_model")

        from intellicrack.tools.train_classifier import generate_synthetic_data

        X, y = generate_synthetic_data(samples_per_class=50)
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        return classifier

    @pytest.fixture
    def learner(self, classifier, tmp_path) -> Any:
        """Create incremental learner instance."""
        buffer_path = tmp_path / "buffer.pkl"
        return IncrementalLearner(
            classifier=classifier,
            buffer_path=buffer_path,
            auto_retrain=False
        )

    @pytest.fixture
    def test_binary(self, tmp_path: Any) -> None:
        """Create a minimal test binary."""
        binary_file = tmp_path / "test.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        pe_data = dos_header + b'\x00' * 64 + b'PE\x00\x00' + b'\x00' * 1000
        pe_data += b'VMProtect' * 100
        pe_data += bytes(np.random.randint(200, 256, size=2000, dtype=np.uint8))

        with open(binary_file, 'wb') as f:
            f.write(pe_data)

        return binary_file

    def test_learner_initialization(self, learner: Any) -> None:
        """Test incremental learner initialization."""
        assert learner.sample_buffer == []
        assert learner.learning_history == []
        assert not learner.auto_retrain

    def test_add_sample(self, learner: Any, test_binary: Any) -> None:
        """Test adding a sample to the buffer."""
        success = learner.add_sample(
            binary_path=test_binary,
            protection_type='VMProtect',
            confidence=0.9,
            source='manual'
        )

        assert success
        assert len(learner.sample_buffer) == 1

        sample = learner.sample_buffer[0]
        assert sample.protection_type == 'VMProtect'
        assert sample.confidence == 0.9
        assert sample.source == 'manual'
        assert sample.feature_vector is not None

    def test_add_multiple_samples(self, learner: Any, tmp_path: Any) -> None:
        """Test adding multiple samples."""
        for i in range(10):
            binary_file = tmp_path / f"test_{i}.exe"

            dos_header = bytearray(64)
            dos_header[:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            protection = 'VMProtect' if i % 2 == 0 else 'Themida'
            learner.add_sample(binary_file, protection, confidence=0.8)

        assert len(learner.sample_buffer) == 10

    def test_buffer_persistence(self, learner: Any, test_binary: Any, tmp_path: Any) -> None:
        """Test that buffer is persisted to disk."""
        learner.add_sample(test_binary, 'VMProtect', confidence=0.9)

        new_learner = IncrementalLearner(
            classifier=learner.classifier,
            buffer_path=learner.buffer_path,
            auto_retrain=False
        )

        assert len(new_learner.sample_buffer) == 1
        assert new_learner.sample_buffer[0].protection_type == 'VMProtect'

    def test_retrain_incremental(self, learner: Any, tmp_path: Any) -> None:
        """Test incremental retraining."""
        for i in range(60):
            binary_file = tmp_path / f"sample_{i}.exe"

            dos_header = bytearray(64)
            dos_header[:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            protection = ['VMProtect', 'Themida', 'UPX'][i % 3]
            learner.add_sample(binary_file, protection, confidence=0.8)

        results = learner.retrain_incremental(n_estimators=50)

        assert 'test_accuracy' in results
        assert len(learner.sample_buffer) == 0

    def test_buffer_statistics(self, learner: Any, tmp_path: Any) -> None:
        """Test buffer statistics calculation."""
        for i in range(20):
            binary_file = tmp_path / f"sample_{i}.exe"

            dos_header = bytearray(64)
            dos_header[:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            protection = 'VMProtect' if i < 10 else 'Themida'
            confidence = 0.9 if i % 2 == 0 else 0.7
            learner.add_sample(binary_file, protection, confidence=confidence)

        stats = learner.get_buffer_statistics()

        assert stats['size'] == 20
        assert 'VMProtect' in stats['classes']
        assert 'Themida' in stats['classes']
        assert stats['classes']['VMProtect'] == 10
        assert stats['classes']['Themida'] == 10
        assert 0.7 <= stats['avg_confidence'] <= 0.9

    def test_evaluate_sample_quality(self, learner: Any, test_binary: Any) -> None:
        """Test sample quality evaluation."""
        learner.add_sample(test_binary, 'VMProtect', confidence=0.9)

        sample = learner.sample_buffer[0]
        quality = learner.evaluate_sample_quality(sample)

        assert 'confidence' in quality
        assert 'source' in quality
        assert 'is_high_quality' in quality
        assert quality['confidence'] == 0.9

    def test_auto_retrain_threshold(self, tmp_path: Any) -> None:
        """Test automatic retraining when threshold is reached."""
        classifier = ProtectionClassifier(model_path=tmp_path / "auto_model")

        from intellicrack.tools.train_classifier import generate_synthetic_data

        X, y = generate_synthetic_data(samples_per_class=50)
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        learner = IncrementalLearner(
            classifier=classifier,
            buffer_path=tmp_path / "auto_buffer.pkl",
            auto_retrain=True
        )

        learner.RETRAIN_THRESHOLD = 10

        for i in range(15):
            binary_file = tmp_path / f"auto_sample_{i}.exe"

            dos_header = bytearray(64)
            dos_header[:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            learner.add_sample(binary_file, 'VMProtect', confidence=0.8)

        assert len(learner.sample_buffer) < 10

    def test_low_confidence_filtering(self, learner: Any, tmp_path: Any) -> None:
        """Test that low confidence samples are filtered during retraining."""
        for i in range(20):
            binary_file = tmp_path / f"sample_{i}.exe"

            dos_header = bytearray(64)
            dos_header[:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            confidence = 0.8 if i < 15 else 0.3
            learner.add_sample(binary_file, 'VMProtect', confidence=confidence)

        results = learner.retrain_incremental(n_estimators=50)

        assert results['n_samples'] == 15
