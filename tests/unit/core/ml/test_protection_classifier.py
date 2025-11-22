"""Tests for ML-based protection classifier.

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

from intellicrack.core.ml.feature_extraction import BinaryFeatureExtractor
from intellicrack.core.ml.protection_classifier import ProtectionClassifier


class TestBinaryFeatureExtractor:
    """Tests for binary feature extraction."""

    @pytest.fixture
    def extractor(self):
        """Create feature extractor instance."""
        return BinaryFeatureExtractor()

    @pytest.fixture
    def valid_pe_binary(self, tmp_path):
        """Create a minimal valid PE binary for testing."""
        pe_file = tmp_path / "test.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x00' * 64

        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 3)
        struct.pack_into('<I', coff_header, 4, 0)
        struct.pack_into('<I', coff_header, 8, 0)
        struct.pack_into('<I', coff_header, 12, 0)
        struct.pack_into('<H', coff_header, 16, 224)
        struct.pack_into('<H', coff_header, 18, 0x010B)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010B)
        struct.pack_into('<B', optional_header, 2, 14)
        struct.pack_into('<B', optional_header, 3, 0)
        struct.pack_into('<I', optional_header, 4, 0x1000)
        struct.pack_into('<I', optional_header, 8, 0x400)
        struct.pack_into('<I', optional_header, 12, 0)
        struct.pack_into('<I', optional_header, 16, 0x1000)

        section_table = bytearray()

        text_section = bytearray(40)
        text_section[0:6] = b'.text\x00'
        struct.pack_into('<I', text_section, 8, 0x1000)
        struct.pack_into('<I', text_section, 12, 0x1000)
        struct.pack_into('<I', text_section, 16, 0x400)
        struct.pack_into('<I', text_section, 20, 0x400)
        struct.pack_into('<I', text_section, 36, 0x60000020)
        section_table.extend(text_section)

        data_section = bytearray(40)
        data_section[0:6] = b'.data\x00'
        struct.pack_into('<I', data_section, 8, 0x200)
        struct.pack_into('<I', data_section, 12, 0x2000)
        struct.pack_into('<I', data_section, 16, 0x200)
        struct.pack_into('<I', data_section, 20, 0x800)
        struct.pack_into('<I', data_section, 36, 0xC0000040)
        section_table.extend(data_section)

        rsrc_section = bytearray(40)
        rsrc_section[0:6] = b'.rsrc\x00'
        struct.pack_into('<I', rsrc_section, 8, 0x200)
        struct.pack_into('<I', rsrc_section, 12, 0x3000)
        struct.pack_into('<I', rsrc_section, 16, 0x200)
        struct.pack_into('<I', rsrc_section, 20, 0xA00)
        struct.pack_into('<I', rsrc_section, 36, 0x40000040)
        section_table.extend(rsrc_section)

        text_data = b'\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57' * 50 + b'\x90' * 574
        data_data = b'Hello World\x00' * 20 + b'\x00' * 272
        rsrc_data = b'RSRC' * 100 + b'\x00' * 112

        pe_binary = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_table +
            text_data +
            data_data +
            rsrc_data
        )

        with open(pe_file, 'wb') as f:
            f.write(pe_binary)

        return pe_file

    @pytest.fixture
    def vmprotect_like_binary(self, tmp_path):
        """Create a binary with VMProtect-like characteristics."""
        pe_file = tmp_path / "vmprotect_test.exe"

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        dos_stub = b'\x00' * 64
        pe_signature = b'PE\x00\x00'

        coff_header = bytearray(20)
        struct.pack_into('<H', coff_header, 0, 0x014c)
        struct.pack_into('<H', coff_header, 2, 2)
        struct.pack_into('<H', coff_header, 16, 224)

        optional_header = bytearray(224)
        struct.pack_into('<H', optional_header, 0, 0x010B)

        section_table = bytearray()

        vmp0_section = bytearray(40)
        vmp0_section[0:6] = b'.vmp0\x00'
        struct.pack_into('<I', vmp0_section, 8, 0x2000)
        struct.pack_into('<I', vmp0_section, 12, 0x1000)
        struct.pack_into('<I', vmp0_section, 16, 0x2000)
        struct.pack_into('<I', vmp0_section, 20, 0x400)
        struct.pack_into('<I', vmp0_section, 36, 0xE0000020)
        section_table.extend(vmp0_section)

        vmp1_section = bytearray(40)
        vmp1_section[0:6] = b'.vmp1\x00'
        struct.pack_into('<I', vmp1_section, 8, 0x1000)
        struct.pack_into('<I', vmp1_section, 12, 0x3000)
        struct.pack_into('<I', vmp1_section, 16, 0x1000)
        struct.pack_into('<I', vmp1_section, 20, 0x2400)
        struct.pack_into('<I', vmp1_section, 36, 0xC0000040)
        section_table.extend(vmp1_section)

        high_entropy_data = bytes(np.random.randint(0, 256, size=8192, dtype=np.uint8))
        medium_entropy_data = bytes(np.random.randint(0, 128, size=4096, dtype=np.uint8))

        vmprotect_string = b'VMProtect markers and patterns\x00' * 10
        suspicious_code = (
            b'\xFF\x15' + b'\x00' * 4 +
            b'\x8B\x0D' + b'\x00' * 4 +
            b'\xFF\xE0' +
            b'\xE8\x00\x00\x00\x00' * 20
        ) * 10

        pe_binary = (
            dos_header +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_table +
            high_entropy_data +
            vmprotect_string +
            suspicious_code +
            medium_entropy_data
        )

        with open(pe_file, 'wb') as f:
            f.write(pe_binary)

        return pe_file

    def test_feature_extraction_valid_binary(self, extractor, valid_pe_binary):
        """Test feature extraction from valid PE binary."""
        features = extractor.extract_features(valid_pe_binary)

        assert isinstance(features, np.ndarray)
        assert features.dtype == np.float32
        assert len(features) == len(extractor.feature_names)

        assert not np.any(np.isnan(features))
        assert not np.any(np.isinf(features))

    def test_feature_extraction_vmprotect_characteristics(
        self, extractor, vmprotect_like_binary
    ):
        """Test that VMProtect-like binaries produce distinctive features."""
        features = extractor.extract_features(vmprotect_like_binary)

        entropy_idx = extractor.feature_names.index('overall_entropy')
        assert features[entropy_idx] > 6.0

        high_entropy_idx = extractor.feature_names.index('high_entropy_section_count')
        assert features[high_entropy_idx] >= 1.0

        unusual_names_idx = extractor.feature_names.index('unusual_section_names')
        assert features[unusual_names_idx] >= 1.0

        vmp_sig_idx = extractor.feature_names.index('signature_vmprotect')
        assert features[vmp_sig_idx] >= 0.6

    def test_feature_extraction_nonexistent_file(self, extractor):
        """Test feature extraction with nonexistent file."""
        with pytest.raises(ValueError, match="Binary file not found"):
            extractor.extract_features("/nonexistent/path/file.exe")

    def test_feature_extraction_invalid_binary(self, extractor, tmp_path):
        """Test feature extraction with invalid binary data."""
        invalid_file = tmp_path / "invalid.exe"
        with open(invalid_file, 'wb') as f:
            f.write(b'This is not a PE file')

        features = extractor.extract_features(invalid_file)

        assert isinstance(features, np.ndarray)
        overall_entropy = features[extractor.feature_names.index('overall_entropy')]
        assert overall_entropy > 0.0

    def test_entropy_calculation(self, extractor):
        """Test entropy calculation accuracy."""
        uniform_data = bytes(range(256))
        entropy = extractor._calculate_entropy(uniform_data)
        assert 7.9 < entropy <= 8.0

        zeros = bytes(1000)
        entropy = extractor._calculate_entropy(zeros)
        assert entropy == 0.0

        half_half = b'\x00' * 500 + b'\xFF' * 500
        entropy = extractor._calculate_entropy(half_half)
        assert 0.9 < entropy < 1.1

    def test_protector_signature_detection(self, extractor, tmp_path):
        """Test sophisticated multi-factor protector detection with scoring system."""
        test_cases = [
            {
                'name': 'vmprotect_byte_only',
                'signature_bytes': b'VMProtect',
                'feature_name': 'signature_vmprotect',
                'expected_score': 0.3,
                'description': 'Byte pattern only (weight 0.3)'
            },
            {
                'name': 'vmprotect_section_only',
                'section_name': b'.vmp0\x00\x00\x00',
                'feature_name': 'signature_vmprotect',
                'expected_score': 0.4,
                'description': 'Section name only (weight 0.4)'
            },
            {
                'name': 'vmprotect_multi_factor',
                'signature_bytes': b'\x9c\x8d\x64',
                'section_name': b'.vmp1\x00\x00\x00',
                'feature_name': 'signature_vmprotect',
                'expected_score': 0.7,
                'description': 'Byte pattern (0.3) + section name (0.4)'
            },
            {
                'name': 'themida_entry_point',
                'signature_bytes': b'Themida',
                'entry_point_sig': b'\xb8\x00\x00\x00\x60',
                'feature_name': 'signature_themida',
                'expected_score': 0.8,
                'description': 'Byte pattern (0.3) + entry point (0.5)'
            },
            {
                'name': 'enigma_timestamp',
                'signature_bytes': b'ENIGMA',
                'timestamp': 0x2A425E19,
                'feature_name': 'signature_enigma',
                'expected_score': 0.9,
                'description': 'Byte pattern (0.3) + timestamp (0.6)'
            },
            {
                'name': 'upx_section',
                'section_name': b'UPX0\x00\x00\x00\x00',
                'signature_bytes': b'UPX!',
                'feature_name': 'signature_upx',
                'expected_score': 0.7,
                'description': 'Section name (0.4) + byte pattern (0.3)'
            },
        ]

        for test_case in test_cases:
            test_file = tmp_path / f"test_{test_case['name']}.exe"

            dos_header = bytearray(64)
            dos_header[0:2] = b'MZ'
            dos_header[60:64] = struct.pack('<I', 128)

            coff_header = bytearray(20)
            coff_header[0:2] = struct.pack('<H', 0x014c)
            coff_header[2:4] = struct.pack('<H', 1)
            coff_header[4:8] = struct.pack('<I', test_case.get('timestamp', 0x12345678))
            coff_header[16:18] = struct.pack('<H', 224)
            coff_header[18:20] = struct.pack('<H', 0x010b)

            optional_header = bytearray(224)
            optional_header[0:2] = struct.pack('<H', 0x010b)
            if 'entry_point_sig' in test_case:
                optional_header[16:20] = struct.pack('<I', 0x1000)

            header_size = 64 + 64 + 4 + 20 + 224 + 40
            section_raw_offset = ((header_size + 511) // 512) * 512

            section_table = bytearray(40)
            section_name = test_case.get('section_name', b'.text\x00\x00\x00')
            section_table[0:8] = section_name
            section_table[8:12] = struct.pack('<I', 1000)
            section_table[12:16] = struct.pack('<I', 0x1000)
            section_table[16:20] = struct.pack('<I', 1000)
            section_table[20:24] = struct.pack('<I', section_raw_offset)
            section_table[36:40] = struct.pack('<I', 0x60000020)

            section_data = bytearray(1000)
            if 'entry_point_sig' in test_case:
                section_data[0:5] = test_case['entry_point_sig']
            if 'signature_bytes' in test_case:
                section_data[500:500+len(test_case['signature_bytes'])] = test_case['signature_bytes']

            padding_size = section_raw_offset - header_size
            pe_data = dos_header + b'\x00' * 64 + b'PE\x00\x00' + coff_header + optional_header + section_table + b'\x00' * padding_size + section_data

            with open(test_file, 'wb') as f:
                f.write(pe_data)

            features = extractor.extract_features(test_file)
            feature_idx = extractor.feature_names.index(test_case['feature_name'])
            actual_score = features[feature_idx]

            assert abs(actual_score - test_case['expected_score']) < 0.15, \
                f"{test_case['description']}: Expected ~{test_case['expected_score']}, got {actual_score}"

    def test_feature_names_completeness(self, extractor):
        """Test that all expected feature names are present."""
        expected_features = [
            'overall_entropy',
            'text_entropy',
            'section_count',
            'import_count',
            'signature_vmprotect',
            'signature_themida',
        ]

        for feature in expected_features:
            assert feature in extractor.feature_names

    def test_feature_vector_consistency(self, extractor, valid_pe_binary):
        """Test that feature extraction is deterministic."""
        features1 = extractor.extract_features(valid_pe_binary)
        features2 = extractor.extract_features(valid_pe_binary)

        np.testing.assert_array_equal(features1, features2)


class TestProtectionClassifier:
    """Tests for protection classifier."""

    @pytest.fixture
    def classifier(self, tmp_path):
        """Create classifier instance with temp model path."""
        model_path = tmp_path / "test_model"
        return ProtectionClassifier(model_path=model_path)

    @pytest.fixture
    def synthetic_training_data(self):
        """Generate synthetic training data for testing."""
        n_samples_per_class = 50
        n_features = len(BinaryFeatureExtractor().feature_names)

        protection_classes = [
            'VMProtect', 'Themida', 'Enigma', 'Obsidium',
            'ASProtect', 'UPX', 'None'
        ]

        X_list = []
        y_list = []

        for idx, protection in enumerate(protection_classes):
            class_features = np.random.randn(n_samples_per_class, n_features).astype(np.float32)

            class_features[:, idx] += 5.0

            X_list.append(class_features)
            y_list.extend([protection] * n_samples_per_class)

        X = np.vstack(X_list)
        y = np.array(y_list)

        return X, y

    def test_classifier_initialization(self, classifier):
        """Test classifier initialization."""
        assert classifier.model is None
        assert classifier.scaler is None
        assert classifier.label_encoder is None

    def test_train_classifier(self, classifier, synthetic_training_data):
        """Test classifier training with synthetic data."""
        X, y = synthetic_training_data

        results = classifier.train(X, y, n_estimators=50, cross_validate=False)

        assert 'train_accuracy' in results
        assert 'test_accuracy' in results
        assert results['train_accuracy'] > 0.5
        assert results['test_accuracy'] > 0.5

        assert classifier.model is not None
        assert classifier.scaler is not None
        assert classifier.label_encoder is not None

    def test_train_classifier_achieves_high_accuracy(self, classifier, synthetic_training_data):
        """Test that classifier achieves >85% accuracy on well-separated data."""
        X, y = synthetic_training_data

        results = classifier.train(
            X, y, n_estimators=100, cross_validate=False, random_state=42
        )

        assert results['test_accuracy'] > 0.85

    def test_cross_validation(self, classifier, synthetic_training_data):
        """Test cross-validation during training."""
        X, y = synthetic_training_data

        results = classifier.train(X, y, n_estimators=50, cross_validate=True)

        assert 'cv_mean_accuracy' in results
        assert 'cv_std_accuracy' in results
        assert results['cv_mean_accuracy'] > 0.5

    def test_save_and_load_model(self, classifier, synthetic_training_data, tmp_path):
        """Test model serialization and deserialization."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        model_path = tmp_path / "saved_model"
        classifier.save_model(output_path=model_path)

        assert (model_path / 'model.pkl').exists()
        assert (model_path / 'scaler.pkl').exists()
        assert (model_path / 'encoder.pkl').exists()
        assert (model_path / 'metadata.json').exists()

        new_classifier = ProtectionClassifier(model_path=model_path)

        assert new_classifier.model is not None
        assert new_classifier.scaler is not None
        assert new_classifier.label_encoder is not None

    def test_predict_without_training(self, classifier, tmp_path):
        """Test that prediction fails without trained model."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b'MZ' + b'\x00' * 100)

        with pytest.raises(RuntimeError, match="Model not loaded"):
            classifier.predict(test_file)

    def test_predict_with_trained_model(
        self, classifier, synthetic_training_data, tmp_path
    ):
        """Test prediction with trained model."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        pe_binary = dos_header + b'\x00' * 64 + b'PE\x00\x00' + b'\x00' * 1000
        pe_binary += b'VMProtect signature here\x00' * 10
        pe_binary += bytes(np.random.randint(200, 256, size=2000, dtype=np.uint8))

        test_file = tmp_path / "test_protected.exe"
        with open(test_file, 'wb') as f:
            f.write(pe_binary)

        result = classifier.predict(test_file)

        assert hasattr(result, 'primary_protection')
        assert hasattr(result, 'confidence')
        assert hasattr(result, 'top_predictions')

        assert isinstance(result.primary_protection, str)
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.top_predictions) == 3

        for protection, prob in result.top_predictions:
            assert isinstance(protection, str)
            assert 0.0 <= prob <= 1.0

    def test_feature_importance(self, classifier, synthetic_training_data):
        """Test feature importance extraction."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        top_features = classifier.get_feature_importance(top_n=10)

        assert len(top_features) == 10

        for feature_name, importance in top_features:
            assert isinstance(feature_name, str)
            assert 0.0 <= importance <= 1.0

    def test_model_metadata(self, classifier, synthetic_training_data, tmp_path):
        """Test that model metadata is correctly saved."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        model_path = tmp_path / "model_with_metadata"
        classifier.save_model(output_path=model_path)

        metadata_file = model_path / 'metadata.json'
        assert metadata_file.exists()

        import json
        with open(metadata_file, encoding='utf-8') as f:
            metadata = json.load(f)

        assert 'model_version' in metadata
        assert 'n_features' in metadata
        assert 'feature_names' in metadata
        assert 'classes' in metadata

    def test_training_with_imbalanced_data(self, classifier):
        """Test training with imbalanced class distribution."""
        n_features = len(BinaryFeatureExtractor().feature_names)

        X_major = np.random.randn(200, n_features).astype(np.float32)
        X_minor = np.random.randn(20, n_features).astype(np.float32) + 3.0

        X = np.vstack([X_major, X_minor])
        y = np.array(['None'] * 200 + ['VMProtect'] * 20)

        results = classifier.train(X, y, n_estimators=50, cross_validate=False)

        assert results['test_accuracy'] > 0.6

    def test_prediction_consistency(self, classifier, synthetic_training_data, tmp_path):
        """Test that predictions are consistent for same input."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False, random_state=42)

        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[60:64] = struct.pack('<I', 128)

        pe_binary = dos_header + b'\x00' * 200 + b'PE\x00\x00' + b'\x00' * 1000

        test_file = tmp_path / "consistent_test.exe"
        with open(test_file, 'wb') as f:
            f.write(pe_binary)

        result1 = classifier.predict(test_file)
        result2 = classifier.predict(test_file)

        assert result1.primary_protection == result2.primary_protection
        assert abs(result1.confidence - result2.confidence) < 1e-6

    def test_model_handles_all_protection_types(
        self, classifier, synthetic_training_data
    ):
        """Test that model can classify all protection types."""
        X, y = synthetic_training_data
        classifier.train(X, y, n_estimators=50, cross_validate=False)

        expected_classes = {'VMProtect', 'Themida', 'Enigma', 'Obsidium',
                                 'ASProtect', 'UPX', 'None'}
        actual_classes = set(classifier.label_encoder.classes_)

        assert expected_classes.issubset(actual_classes)


@pytest.mark.integration
class TestProtectionClassifierIntegration:
    """Integration tests for full classification pipeline."""

    def test_full_pipeline_synthetic_data(self, tmp_path):
        """Test complete training and prediction pipeline."""
        from intellicrack.tools.train_classifier import generate_synthetic_data

        X, y = generate_synthetic_data(samples_per_class=100)

        assert X.shape[0] == 800
        assert len(y) == 800

        classifier = ProtectionClassifier(model_path=tmp_path / "integration_model")
        results = classifier.train(X, y, n_estimators=100, cross_validate=True)

        assert results['test_accuracy'] > 0.65
        assert results['cv_mean_accuracy'] > 0.65

        classifier.save_model()

        new_classifier = ProtectionClassifier(model_path=tmp_path / "integration_model")

        assert new_classifier.model is not None
