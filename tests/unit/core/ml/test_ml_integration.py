"""Tests for ML integration layer.

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

from intellicrack.core.ml.ml_integration import MLAnalysisIntegration
from intellicrack.core.ml.protection_classifier import ProtectionClassifier


class TestMLAnalysisIntegration:
    """Tests for ML analysis integration."""

    @pytest.fixture
    def trained_integration(self, tmp_path):
        """Create integration with trained model."""
        model_path = tmp_path / "integration_model"

        classifier = ProtectionClassifier(model_path=model_path)

        from intellicrack.tools.train_classifier import generate_synthetic_data

        X, y = generate_synthetic_data(samples_per_class=50)
        classifier.train(X, y, n_estimators=50, cross_validate=False)
        classifier.save_model()

        integration = MLAnalysisIntegration(
            model_path=model_path,
            enable_incremental_learning=True,
            enable_sample_database=True
        )

        return integration

    @pytest.fixture
    def test_binary(self, tmp_path):
        """Create test binary."""
        binary_file = tmp_path / "integration_test.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        pe_data = dos_header + b'\x00' * 64 + b'PE\x00\x00'
        pe_data += b'\x00' * 1000 + b'VMProtect' * 100
        pe_data += bytes(np.random.randint(200, 256, size=2000, dtype=np.uint8))

        with open(binary_file, 'wb') as f:
            f.write(pe_data)

        return binary_file

    def test_integration_initialization_with_model(self, trained_integration):
        """Test integration initialization with trained model."""
        assert trained_integration.enabled
        assert trained_integration.classifier.model is not None
        assert trained_integration.incremental_learner is not None
        assert trained_integration.sample_database is not None

    def test_integration_initialization_without_model(self, tmp_path):
        """Test integration initialization without trained model."""
        integration = MLAnalysisIntegration(
            model_path=tmp_path / "nonexistent_model"
        )

        assert not integration.enabled
        assert integration.incremental_learner is None

    def test_classify_binary(self, trained_integration, test_binary):
        """Test binary classification."""
        result = trained_integration.classify_binary(test_binary)

        assert result['enabled']
        assert 'primary_protection' in result
        assert 'confidence' in result
        assert 'confidence_level' in result
        assert 'reliable' in result
        assert 'alternatives' in result

        assert 0.0 <= result['confidence'] <= 1.0
        assert result['confidence_level'] in [
            'very_low', 'low', 'medium', 'high', 'very_high'
        ]

    def test_classify_binary_disabled(self, tmp_path, test_binary):
        """Test classification when ML is disabled."""
        integration = MLAnalysisIntegration(
            model_path=tmp_path / "nonexistent"
        )

        result = integration.classify_binary(test_binary)

        assert not result['enabled']
        assert 'error' in result

    def test_analyze_with_ml(self, trained_integration, test_binary):
        """Test comprehensive ML analysis."""
        results = trained_integration.analyze_with_ml(test_binary)

        assert 'binary_path' in results
        assert 'ml_enabled' in results
        assert 'classification' in results

        if results['classification'].get('reliable'):
            assert 'recommended_tools' in results

    def test_add_verified_sample(self, trained_integration, test_binary):
        """Test adding verified sample."""
        success = trained_integration.add_verified_sample(
            binary_path=test_binary,
            protection_type='VMProtect',
            verified=True,
            notes='Test verified sample'
        )

        assert success

        buffer_stats = trained_integration.incremental_learner.get_buffer_statistics()
        assert buffer_stats['size'] == 1

        db_stats = trained_integration.sample_database.get_statistics()
        assert db_stats['total_samples'] == 1

    def test_get_learning_statistics(self, trained_integration):
        """Test getting learning statistics."""
        stats = trained_integration.get_learning_statistics()

        assert 'ml_enabled' in stats
        assert stats['ml_enabled']
        assert 'model_info' in stats
        assert 'incremental_learning' in stats
        assert 'sample_database' in stats

        model_info = stats['model_info']
        assert 'version' in model_info
        assert 'n_features' in model_info
        assert 'classes' in model_info

    def test_confidence_level_categorization(self, trained_integration):
        """Test confidence level categorization."""
        assert trained_integration._get_confidence_level(0.95) == 'very_high'
        assert trained_integration._get_confidence_level(0.80) == 'high'
        assert trained_integration._get_confidence_level(0.60) == 'medium'
        assert trained_integration._get_confidence_level(0.35) == 'low'
        assert trained_integration._get_confidence_level(0.15) == 'very_low'

    def test_recommended_tools(self, trained_integration):
        """Test tool recommendations."""
        tools = trained_integration._get_recommended_tools('VMProtect')

        assert 'unpackers' in tools or 'analyzers' in tools
        assert isinstance(tools, dict)

    def test_retrain_from_database(self, trained_integration, tmp_path):
        """Test retraining from sample database."""
        for i in range(60):
            binary_file = tmp_path / f"retrain_{i}.exe"

            dos_header = bytearray(64)
            dos_header[0:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            protection = ['VMProtect', 'Themida', 'UPX'][i % 3]

            trained_integration.add_verified_sample(
                binary_file,
                protection,
                verified=True
            )

        results = trained_integration.retrain_model(
            use_database=True,
            min_confidence=0.7,
            n_estimators=50
        )

        assert 'test_accuracy' in results or 'error' not in results

    def test_multiple_classifications(self, trained_integration, tmp_path):
        """Test classifying multiple binaries."""
        binaries = []

        for i in range(5):
            binary_file = tmp_path / f"multi_{i}.exe"

            dos_header = bytearray(64)
            dos_header[0:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            pe_data = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

            with open(binary_file, 'wb') as f:
                f.write(pe_data)

            binaries.append(binary_file)

        results = []
        for binary in binaries:
            result = trained_integration.classify_binary(binary)
            results.append(result)

        assert len(results) == 5
        assert all(r['enabled'] for r in results)

    def test_integration_with_high_confidence_sample(self, trained_integration, tmp_path):
        """Test that high-confidence predictions are correctly identified."""
        binary_file = tmp_path / "high_conf.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        coff_header = bytearray(20)
        coff_header[0:2] = struct.pack('<H', 0x014c)
        coff_header[2:4] = struct.pack('<H', 1)
        coff_header[16:18] = struct.pack('<H', 224)

        optional_header = bytearray(224)
        optional_header[0:2] = struct.pack('<H', 0x010b)

        section_table = bytearray(40)
        section_table[0:6] = b'.vmp0\x00'
        section_table[36:40] = struct.pack('<I', 0x60000020)

        high_entropy = bytes(np.random.randint(0, 256, size=4096, dtype=np.uint8))

        pe_data = (
            dos_header + b'\x00' * 64 + b'PE\x00\x00' +
            coff_header + optional_header + section_table +
            b'VMProtect' * 100 + high_entropy
        )

        with open(binary_file, 'wb') as f:
            f.write(pe_data)

        result = trained_integration.classify_binary(binary_file)

        assert result['enabled']
        assert 'confidence' in result
