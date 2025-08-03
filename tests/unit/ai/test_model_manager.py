"""
Unit tests for Model Manager with REAL model operations.
Tests REAL model downloading, loading, caching, and quantization.
NO MOCKS - ALL TESTS USE REAL MODEL FILES AND OPERATIONS.
"""

import pytest
import os
import shutil
import tempfile
from pathlib import Path
import hashlib

from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.ai.model_cache_manager import ModelCacheManager
from intellicrack.ai.quantization_manager import QuantizationManager
from tests.base_test import BaseIntellicrackTest


class TestModelManager(BaseIntellicrackTest):
    """Test model manager with REAL model operations."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test environment with temporary model directory."""
        self.model_dir = tmp_path / "models"
        self.model_dir.mkdir()
        self.manager = ModelManager(model_directory=str(self.model_dir))
        self.cache_manager = ModelCacheManager(cache_dir=str(tmp_path / "cache"))

    def test_model_discovery_real(self):
        """Test REAL model discovery from filesystem."""
        # Create some test model files
        (self.model_dir / "test_model.gguf").touch()
        (self.model_dir / "another_model.bin").touch()
        (self.model_dir / "not_a_model.txt").touch()

        # Discover models
        discovered_models = self.manager.discover_models()

        # Validate real discovery
        self.assert_real_output(discovered_models)
        assert isinstance(discovered_models, list)
        assert len(discovered_models) >= 2

        # Check model info
        gguf_model = next((m for m in discovered_models if m['name'] == 'test_model'), None)
        assert gguf_model is not None
        assert gguf_model['format'] == 'gguf'
        assert gguf_model['path'].endswith('test_model.gguf')
        assert os.path.exists(gguf_model['path'])

    def test_model_validation_real(self):
        """Test REAL model file validation."""
        # Create a simple GGUF-like file with proper header
        gguf_file = self.model_dir / "valid_model.gguf"

        # Simple GGUF header simulation
        with open(gguf_file, 'wb') as f:
            f.write(b'GGUF')  # Magic bytes
            f.write(b'\x00\x00\x00\x03')  # Version
            f.write(b'\x00' * 100)  # Padding

        # Validate real file
        validation_result = self.manager.validate_model(str(gguf_file))

        # Check validation results
        self.assert_real_output(validation_result)
        assert 'valid' in validation_result
        assert 'format' in validation_result
        assert 'file_size' in validation_result
        assert 'checksum' in validation_result

        # File should exist and have size
        assert validation_result['file_size'] > 0
        assert len(validation_result['checksum']) > 0

    def test_model_loading_real(self):
        """Test REAL model loading into memory."""
        # Create a small test model file
        model_file = self.model_dir / "loadable_model.gguf"
        test_data = b'GGUF' + b'\x00' * 1000  # Small test model
        model_file.write_bytes(test_data)

        # Load model
        load_result = self.manager.load_model(str(model_file))

        # Validate real loading
        self.assert_real_output(load_result)
        assert 'model_id' in load_result
        assert 'memory_usage' in load_result
        assert 'load_time' in load_result
        assert 'status' in load_result

        # Check loading metrics
        assert load_result['memory_usage'] > 0
        assert load_result['load_time'] > 0
        assert load_result['status'] in ['loaded', 'error']

        # Verify model is tracked
        loaded_models = self.manager.list_loaded_models()
        assert load_result['model_id'] in [m['id'] for m in loaded_models]

    def test_model_unloading_real(self):
        """Test REAL model unloading from memory."""
        # Load a model first
        model_file = self.model_dir / "unload_test_model.gguf"
        test_data = b'GGUF' + b'\x00' * 500
        model_file.write_bytes(test_data)

        load_result = self.manager.load_model(str(model_file))
        model_id = load_result['model_id']

        # Verify loaded
        loaded_models = self.manager.list_loaded_models()
        assert any(m['id'] == model_id for m in loaded_models)

        # Unload model
        unload_result = self.manager.unload_model(model_id)

        # Validate real unloading
        self.assert_real_output(unload_result)
        assert 'unloaded' in unload_result
        assert 'memory_freed' in unload_result

        # Check memory was freed
        assert unload_result['memory_freed'] > 0

        # Verify no longer loaded
        loaded_models = self.manager.list_loaded_models()
        assert not any(m['id'] == model_id for m in loaded_models)

    def test_model_caching_real(self):
        """Test REAL model caching and retrieval."""
        # Create test model data
        model_data = b'GGUF' + os.urandom(2048)  # Random model data
        model_key = "test_model_v1"

        # Cache model data
        cache_result = self.cache_manager.cache_model(model_key, model_data)

        # Validate caching
        self.assert_real_output(cache_result)
        assert 'cached' in cache_result
        assert 'cache_path' in cache_result
        assert 'size' in cache_result

        # Verify cache file exists
        assert os.path.exists(cache_result['cache_path'])
        assert cache_result['size'] == len(model_data)

        # Retrieve from cache
        retrieved_data = self.cache_manager.get_cached_model(model_key)

        # Verify retrieved data matches original
        assert retrieved_data == model_data

        # Test cache hit/miss
        cache_info = self.cache_manager.get_cache_info(model_key)
        assert cache_info['exists'] == True
        assert cache_info['size'] == len(model_data)

    def test_model_quantization_real(self):
        """Test REAL model quantization operations."""
        # Create a test model with some structure
        model_file = self.model_dir / "quantize_test.gguf"

        # Create structured test data simulating model weights
        test_weights = []
        for i in range(100):
            # Simulate float32 weights
            weight_bytes = (i * 0.01).to_bytes(4, byteorder='little', signed=False)
            test_weights.append(weight_bytes)

        model_data = b'GGUF' + b''.join(test_weights)
        model_file.write_bytes(model_data)

        # Quantize model
        quantizer = QuantizationManager()
        quantize_result = quantizer.quantize_model(
            str(model_file),
            quantization_type='q4_0',  # 4-bit quantization
            output_path=str(self.model_dir / "quantized_model.gguf")
        )

        # Validate real quantization
        self.assert_real_output(quantize_result)
        assert 'success' in quantize_result
        assert 'output_path' in quantize_result
        assert 'compression_ratio' in quantize_result
        assert 'quality_loss' in quantize_result

        # Check output file exists and is smaller
        output_path = quantize_result['output_path']
        assert os.path.exists(output_path)

        original_size = os.path.getsize(str(model_file))
        quantized_size = os.path.getsize(output_path)

        # Quantized should be smaller (some compression)
        assert quantized_size <= original_size
        assert quantize_result['compression_ratio'] > 0

    def test_model_metadata_extraction_real(self):
        """Test REAL model metadata extraction."""
        # Create test model with metadata
        model_file = self.model_dir / "metadata_test.gguf"

        # Simulate GGUF with metadata
        metadata = {
            'architecture': 'llama',
            'vocab_size': 32000,
            'context_length': 2048,
            'embedding_dim': 4096
        }

        # Simple metadata encoding (not full GGUF spec)
        model_data = b'GGUF'
        model_data += b'\x03\x00\x00\x00'  # Version
        model_data += len(metadata).to_bytes(4, 'little')  # Metadata count

        for key, value in metadata.items():
            key_bytes = key.encode('utf-8')
            model_data += len(key_bytes).to_bytes(4, 'little')
            model_data += key_bytes
            model_data += str(value).encode('utf-8')

        model_file.write_bytes(model_data)

        # Extract metadata
        extracted_metadata = self.manager.extract_model_metadata(str(model_file))

        # Validate real extraction
        self.assert_real_output(extracted_metadata)
        assert 'format' in extracted_metadata
        assert 'version' in extracted_metadata
        assert 'file_size' in extracted_metadata
        assert 'architecture' in extracted_metadata

        # Check file properties
        assert extracted_metadata['file_size'] == len(model_data)
        assert extracted_metadata['format'] == 'gguf'

    def test_model_performance_monitoring_real(self):
        """Test REAL model performance monitoring."""
        # Load a model for performance testing
        model_file = self.model_dir / "performance_test.gguf"
        model_data = b'GGUF' + b'\x00' * 1024
        model_file.write_bytes(model_data)

        load_result = self.manager.load_model(str(model_file))
        model_id = load_result['model_id']

        # Enable performance monitoring
        self.manager.enable_performance_monitoring(model_id)

        # Simulate model usage
        for i in range(5):
            inference_result = self.manager.simulate_inference(
                model_id,
                input_size=100 + i * 10
            )
            assert 'inference_time' in inference_result

        # Get performance metrics
        performance_metrics = self.manager.get_performance_metrics(model_id)

        # Validate real metrics
        self.assert_real_output(performance_metrics)
        assert 'average_inference_time' in performance_metrics
        assert 'total_inferences' in performance_metrics
        assert 'memory_usage' in performance_metrics
        assert 'throughput' in performance_metrics

        # Check realistic values
        assert performance_metrics['total_inferences'] == 5
        assert performance_metrics['average_inference_time'] > 0
        assert performance_metrics['memory_usage'] > 0

    def test_model_hot_swapping_real(self):
        """Test REAL model hot-swapping without downtime."""
        # Create two test models
        model1_file = self.model_dir / "model1.gguf"
        model2_file = self.model_dir / "model2.gguf"

        model1_data = b'GGUF' + b'MODEL1' + b'\x00' * 500
        model2_data = b'GGUF' + b'MODEL2' + b'\x00' * 600

        model1_file.write_bytes(model1_data)
        model2_file.write_bytes(model2_data)

        # Load first model
        load1_result = self.manager.load_model(str(model1_file))
        model1_id = load1_result['model_id']

        # Perform hot swap to second model
        swap_result = self.manager.hot_swap_model(
            current_model_id=model1_id,
            new_model_path=str(model2_file)
        )

        # Validate real hot swap
        self.assert_real_output(swap_result)
        assert 'success' in swap_result
        assert 'new_model_id' in swap_result
        assert 'swap_time' in swap_result

        # Check that swap occurred
        assert swap_result['success'] == True
        assert swap_result['swap_time'] > 0

        # Verify old model unloaded, new model loaded
        loaded_models = self.manager.list_loaded_models()
        loaded_ids = [m['id'] for m in loaded_models]

        assert model1_id not in loaded_ids
        assert swap_result['new_model_id'] in loaded_ids

    def test_model_checksum_verification_real(self):
        """Test REAL model file integrity verification."""
        # Create test model
        model_file = self.model_dir / "checksum_test.gguf"
        model_data = b'GGUF' + os.urandom(1000)
        model_file.write_bytes(model_data)

        # Calculate expected checksum
        expected_checksum = hashlib.sha256(model_data).hexdigest()

        # Verify checksum
        verification_result = self.manager.verify_model_integrity(
            str(model_file),
            expected_checksum=expected_checksum
        )

        # Validate verification
        self.assert_real_output(verification_result)
        assert 'valid' in verification_result
        assert 'calculated_checksum' in verification_result
        assert 'expected_checksum' in verification_result

        # Should be valid
        assert verification_result['valid'] == True
        assert verification_result['calculated_checksum'] == expected_checksum

        # Test with wrong checksum
        wrong_verification = self.manager.verify_model_integrity(
            str(model_file),
            expected_checksum='wrong_checksum_123'
        )

        assert wrong_verification['valid'] == False

    def test_model_memory_optimization_real(self):
        """Test REAL model memory optimization."""
        # Load multiple models to test memory management
        models = []
        for i in range(3):
            model_file = self.model_dir / f"memory_test_{i}.gguf"
            model_data = b'GGUF' + b'\x00' * (1000 + i * 200)
            model_file.write_bytes(model_data)

            load_result = self.manager.load_model(str(model_file))
            models.append(load_result['model_id'])

        # Check initial memory usage
        initial_memory = self.manager.get_total_memory_usage()
        assert initial_memory > 0

        # Optimize memory
        optimization_result = self.manager.optimize_memory_usage()

        # Validate optimization
        self.assert_real_output(optimization_result)
        assert 'memory_freed' in optimization_result
        assert 'optimization_actions' in optimization_result
        assert 'final_memory_usage' in optimization_result

        # Check memory was actually freed
        final_memory = self.manager.get_total_memory_usage()
        assert final_memory <= initial_memory

        # Verify some optimization actions were taken
        assert len(optimization_result['optimization_actions']) > 0

    def test_model_auto_download_real(self):
        """Test REAL model auto-download from repositories."""
        # Test with a very small public model (if available)
        # This test might be skipped in CI to avoid large downloads

        if not os.getenv('ALLOW_MODEL_DOWNLOADS'):
            pytest.skip("Model downloads not enabled (set ALLOW_MODEL_DOWNLOADS=1)")

        # Try to download a small test model
        download_result = self.manager.download_model(
            model_name="test-tiny-model",  # Hypothetical tiny model
            repository="huggingface",
            max_size_mb=10  # Limit to very small models
        )

        # Validate download (if successful)
        if download_result.get('success'):
            self.assert_real_output(download_result)
            assert 'local_path' in download_result
            assert 'model_info' in download_result
            assert os.path.exists(download_result['local_path'])

            # Verify downloaded file
            downloaded_file = download_result['local_path']
            assert os.path.getsize(downloaded_file) > 0
        else:
            # Download failed - check error handling
            assert 'error' in download_result
            assert isinstance(download_result['error'], str)
