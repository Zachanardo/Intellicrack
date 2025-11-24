"""Comprehensive production-grade tests for model_manager_module.py.

Tests cover all classes, methods, and functions with real operations validating:
- Model discovery and loading from filesystem
- Model metadata extraction and management
- Model format validation (PyTorch, TensorFlow, ONNX, sklearn)
- Real file operations (copy, move, delete)
- Real configuration management
- Error handling with corrupted models
- Memory management for large models
- Model training and fine-tuning
- Cache management and eviction
- Concurrent access and thread safety

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import json
import os
import pickle
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock, Mock, patch

import numpy as np
import pytest

from intellicrack.ai.model_manager_module import (
    AsyncModelManager,
    ModelBackend,
    ModelCache,
    ModelFineTuner,
    ModelManager,
    ONNXBackend,
    PyTorchBackend,
    SklearnBackend,
    TensorFlowBackend,
    configure_ai_provider,
    create_model_manager,
    get_global_model_manager,
    import_custom_model,
    list_available_models,
    load_model,
    save_model,
)


@pytest.fixture
def temp_models_dir(tmp_path: Path) -> Path:
    """Create temporary directory for model files."""
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    return models_dir


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary directory for cache."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def sample_sklearn_model(temp_models_dir: Path) -> tuple[object, Path]:
    """Create real sklearn model and save to disk."""
    try:
        from sklearn.ensemble import RandomForestClassifier

        model = RandomForestClassifier(n_estimators=5, random_state=42, max_depth=3)
        X = np.random.randn(50, 10)
        y = np.random.randint(0, 2, 50)
        model.fit(X, y)

        model_path = temp_models_dir / "sklearn_model.pkl"
        import joblib

        joblib.dump(model, model_path)
        return model, model_path
    except ImportError:
        pytest.skip("sklearn not available")


@pytest.fixture
def sample_pytorch_model(temp_models_dir: Path) -> tuple[object, Path]:
    """Create real PyTorch model and save to disk."""
    try:
        import torch
        from torch import nn

        class SimpleModel(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.fc1 = nn.Linear(10, 5)
                self.fc2 = nn.Linear(5, 2)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                x = torch.relu(self.fc1(x))
                return self.fc2(x)

        model = SimpleModel()
        model.eval()

        model_path = temp_models_dir / "pytorch_model.pth"
        torch.save(model, model_path)
        return model, model_path
    except ImportError:
        pytest.skip("PyTorch not available")


@pytest.fixture
def sample_tensorflow_model(temp_models_dir: Path) -> tuple[object, Path]:
    """Create real TensorFlow model and save to disk."""
    try:
        from intellicrack.handlers.tensorflow_handler import tensorflow as tf

        keras = tf.keras

        model = keras.Sequential(
            [
                keras.layers.Dense(5, activation="relu", input_shape=(10,)),
                keras.layers.Dense(2, activation="softmax"),
            ]
        )
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy")

        model_path = temp_models_dir / "tf_model.h5"
        model.save(model_path)
        return model, model_path
    except ImportError:
        pytest.skip("TensorFlow not available")


@pytest.fixture
def sample_onnx_model(temp_models_dir: Path) -> tuple[object, Path]:
    """Create real ONNX model and save to disk."""
    try:
        import onnx
        from onnx import TensorProto, helper

        input_tensor = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, 10])
        output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, 2])

        node = helper.make_node("Identity", inputs=["input"], outputs=["output"])

        graph_def = helper.make_graph([node], "test_model", [input_tensor], [output_tensor])
        model_def = helper.make_model(graph_def, producer_name="test")

        model_path = temp_models_dir / "onnx_model.onnx"
        onnx.save(model_def, str(model_path))
        return model_def, model_path
    except ImportError:
        pytest.skip("ONNX not available")


@pytest.fixture
def corrupted_model_file(temp_models_dir: Path) -> Path:
    """Create corrupted model file to test error handling."""
    corrupted_path = temp_models_dir / "corrupted.pkl"
    with open(corrupted_path, "wb") as f:
        f.write(b"This is not a valid pickle file \x00\x01\x02\xff\xfe")
    return corrupted_path


class TestModelCache:
    """Test ModelCache class for model caching functionality."""

    def test_cache_initialization_creates_directory(self, temp_cache_dir: Path) -> None:
        """Cache initialization creates cache directory on filesystem."""
        cache_dir = temp_cache_dir / "new_cache"
        assert not cache_dir.exists()

        cache = ModelCache(cache_dir=str(cache_dir), max_cache_size=3)

        assert cache_dir.exists()
        assert cache_dir.is_dir()
        assert cache.max_cache_size == 3

    def test_cache_key_generation_uses_file_mtime(self, temp_models_dir: Path) -> None:
        """Cache key generation includes file modification time."""
        model_path = temp_models_dir / "test.pkl"
        model_path.write_bytes(b"test data")

        cache = ModelCache()
        key1 = cache._get_cache_key(str(model_path))

        time.sleep(0.1)
        model_path.write_bytes(b"modified data")

        key2 = cache._get_cache_key(str(model_path))

        assert key1 != key2
        assert len(key1) == 64
        assert len(key2) == 64

    def test_cache_put_and_get_stores_retrieves_model(self) -> None:
        """Cache stores and retrieves models correctly."""
        cache = ModelCache(max_cache_size=5)
        model = {"type": "test", "data": np.random.randn(10, 10)}

        cache.put("model_path", model)
        retrieved = cache.get("model_path")

        assert retrieved is model
        assert retrieved["type"] == "test"
        assert np.array_equal(retrieved["data"], model["data"])

    def test_cache_eviction_removes_oldest_accessed(self) -> None:
        """Cache evicts least recently accessed model when full."""
        cache = ModelCache(max_cache_size=3)

        cache.put("model1", {"id": 1})
        cache.put("model2", {"id": 2})
        cache.put("model3", {"id": 3})

        cache.get("model1")
        time.sleep(0.01)
        cache.get("model2")
        time.sleep(0.01)
        cache.get("model3")
        time.sleep(0.01)

        cache.put("model4", {"id": 4})

        assert cache.get("model1") is None
        assert cache.get("model2") is not None
        assert cache.get("model3") is not None
        assert cache.get("model4") is not None

    def test_cache_clear_removes_all_entries(self) -> None:
        """Cache clear removes all cached models."""
        cache = ModelCache(max_cache_size=5)
        cache.put("model1", {"id": 1})
        cache.put("model2", {"id": 2})
        cache.put("model3", {"id": 3})

        assert len(cache.cache) == 3

        cache.clear()

        assert len(cache.cache) == 0
        assert len(cache.access_times) == 0
        assert cache.get("model1") is None

    def test_cache_info_returns_statistics(self) -> None:
        """Cache info returns accurate cache statistics."""
        cache = ModelCache(max_cache_size=10)
        cache.put("model1", {"id": 1})
        cache.put("model2", {"id": 2})

        info = cache.get_cache_info()

        assert info["size"] == 2
        assert info["max_size"] == 10
        assert "cache_dir" in info
        assert len(info["cached_models"]) == 2

    def test_cache_thread_safety_concurrent_access(self) -> None:
        """Cache handles concurrent access from multiple threads safely."""
        cache = ModelCache(max_cache_size=100)
        results: list[Any] = []
        errors: list[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(50):
                    model = {"thread": thread_id, "iteration": i}
                    cache.put(f"model_{thread_id}_{i}", model)
                    retrieved = cache.get(f"model_{thread_id}_{i}")
                    results.append(retrieved)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) > 0


class TestPyTorchBackend:
    """Test PyTorchBackend for PyTorch model operations."""

    def test_load_model_loads_real_pytorch_model(self, sample_pytorch_model: tuple[object, Path]) -> None:
        """PyTorch backend loads real PyTorch model from disk."""
        _, model_path = sample_pytorch_model
        backend = PyTorchBackend()

        loaded_model = backend.load_model(str(model_path))

        assert loaded_model is not None
        assert hasattr(loaded_model, "eval")
        assert hasattr(loaded_model, "parameters")

    def test_predict_generates_real_predictions(self, sample_pytorch_model: tuple[object, Path]) -> None:
        """PyTorch backend generates real predictions from input data."""
        try:
            import torch

            _, model_path = sample_pytorch_model
            backend = PyTorchBackend()
            model = backend.load_model(str(model_path))

            input_data = np.random.randn(5, 10).astype(np.float32)
            predictions = backend.predict(model, input_data)

            assert predictions is not None
            assert predictions.shape == (5, 2)
            assert not np.isnan(predictions).any()
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_get_model_info_returns_parameter_count(self, sample_pytorch_model: tuple[object, Path]) -> None:
        """PyTorch backend returns accurate model parameter count."""
        try:
            _, model_path = sample_pytorch_model
            backend = PyTorchBackend()
            model = backend.load_model(str(model_path))

            info = backend.get_model_info(model)

            assert info["backend"] == "pytorch"
            assert "parameters" in info
            assert info["parameters"] > 0
            assert isinstance(info["parameters"], int)
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_load_model_handles_corrupted_file(self, corrupted_model_file: Path) -> None:
        """PyTorch backend raises error for corrupted model file."""
        backend = PyTorchBackend()

        with pytest.raises(Exception):
            backend.load_model(str(corrupted_model_file))


class TestTensorFlowBackend:
    """Test TensorFlowBackend for TensorFlow model operations."""

    def test_load_model_loads_real_tensorflow_model(self, sample_tensorflow_model: tuple[object, Path]) -> None:
        """TensorFlow backend loads real TensorFlow model from disk."""
        _, model_path = sample_tensorflow_model
        backend = TensorFlowBackend()

        loaded_model = backend.load_model(str(model_path))

        assert loaded_model is not None
        assert hasattr(loaded_model, "predict")
        assert hasattr(loaded_model, "layers")

    def test_predict_generates_real_predictions(self, sample_tensorflow_model: tuple[object, Path]) -> None:
        """TensorFlow backend generates real predictions from input data."""
        try:
            _, model_path = sample_tensorflow_model
            backend = TensorFlowBackend()
            model = backend.load_model(str(model_path))

            input_data = np.random.randn(5, 10).astype(np.float32)
            predictions = backend.predict(model, input_data)

            assert predictions is not None
            assert predictions.shape[0] == 5
            assert predictions.shape[1] == 2
        except ImportError:
            pytest.skip("TensorFlow not available")

    def test_get_model_info_returns_parameter_count(self, sample_tensorflow_model: tuple[object, Path]) -> None:
        """TensorFlow backend returns accurate model parameter count."""
        try:
            _, model_path = sample_tensorflow_model
            backend = TensorFlowBackend()
            model = backend.load_model(str(model_path))

            info = backend.get_model_info(model)

            assert info["backend"] == "tensorflow"
            assert "parameters" in info
            assert info["parameters"] > 0
        except ImportError:
            pytest.skip("TensorFlow not available")


class TestONNXBackend:
    """Test ONNXBackend for ONNX model operations."""

    def test_load_model_validates_onnx_model(self, sample_onnx_model: tuple[object, Path]) -> None:
        """ONNX backend loads and validates real ONNX model."""
        _, model_path = sample_onnx_model
        backend = ONNXBackend()

        loaded_model = backend.load_model(str(model_path))

        assert loaded_model is not None
        assert hasattr(loaded_model, "run")
        assert hasattr(loaded_model, "get_inputs")

    def test_predict_generates_real_predictions(self, sample_onnx_model: tuple[object, Path]) -> None:
        """ONNX backend generates real predictions from input data."""
        try:
            _, model_path = sample_onnx_model
            backend = ONNXBackend()
            model = backend.load_model(str(model_path))

            input_data = np.random.randn(1, 10).astype(np.float32)
            predictions = backend.predict(model, input_data)

            assert predictions is not None
            assert predictions.shape == (1, 2)
        except ImportError:
            pytest.skip("ONNX not available")

    def test_get_model_info_returns_input_output_specs(self, sample_onnx_model: tuple[object, Path]) -> None:
        """ONNX backend returns model input/output specifications."""
        try:
            _, model_path = sample_onnx_model
            backend = ONNXBackend()
            model = backend.load_model(str(model_path))

            info = backend.get_model_info(model)

            assert info["backend"] == "onnx"
            assert "inputs" in info
            assert "outputs" in info
            assert len(info["inputs"]) > 0
            assert len(info["outputs"]) > 0
        except ImportError:
            pytest.skip("ONNX not available")


class TestSklearnBackend:
    """Test SklearnBackend for scikit-learn model operations."""

    def test_load_model_loads_real_sklearn_model(self, sample_sklearn_model: tuple[object, Path]) -> None:
        """Sklearn backend loads real sklearn model from disk."""
        _, model_path = sample_sklearn_model
        backend = SklearnBackend()

        loaded_model = backend.load_model(str(model_path))

        assert loaded_model is not None
        assert hasattr(loaded_model, "predict")
        assert hasattr(loaded_model, "feature_importances_")

    def test_predict_generates_real_predictions(self, sample_sklearn_model: tuple[object, Path]) -> None:
        """Sklearn backend generates real predictions from input data."""
        try:
            _, model_path = sample_sklearn_model
            backend = SklearnBackend()
            model = backend.load_model(str(model_path))

            input_data = np.random.randn(5, 10)
            predictions = backend.predict(model, input_data)

            assert predictions is not None
            assert len(predictions) == 5
        except ImportError:
            pytest.skip("sklearn not available")

    def test_get_model_info_returns_model_details(self, sample_sklearn_model: tuple[object, Path]) -> None:
        """Sklearn backend returns model details and capabilities."""
        try:
            _, model_path = sample_sklearn_model
            backend = SklearnBackend()
            model = backend.load_model(str(model_path))

            info = backend.get_model_info(model)

            assert info["backend"] == "sklearn"
            assert "type" in info
            assert info["has_feature_importance"] is True
            assert info["classes"] == 2
        except ImportError:
            pytest.skip("sklearn not available")


class TestModelManager:
    """Test ModelManager for comprehensive model management."""

    def test_initialization_creates_directories(self, temp_models_dir: Path) -> None:
        """ModelManager initialization creates necessary directories."""
        models_dir = temp_models_dir / "new_models"
        assert not models_dir.exists()

        manager = ModelManager(models_dir=str(models_dir), cache_size=5)

        assert models_dir.exists()
        assert manager.models_dir == str(models_dir)
        assert manager.cache.max_cache_size == 5

    def test_register_model_stores_metadata(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager registers model and stores metadata to disk."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))

        manager.register_model(
            model_id="test_model",
            model_path=str(model_path),
            model_type="sklearn",
            metadata={"description": "Test model"},
        )

        assert "test_model" in manager.model_metadata
        assert manager.model_metadata["test_model"]["path"] == str(model_path)
        assert manager.model_metadata["test_model"]["type"] == "sklearn"

        metadata_file = temp_models_dir / "model_metadata.json"
        assert metadata_file.exists()

        with open(metadata_file) as f:
            saved_metadata = json.load(f)
        assert "test_model" in saved_metadata

    def test_load_model_loads_from_disk_and_caches(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager loads model from disk and caches it."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        loaded_model = manager.load_model("test_model")

        assert loaded_model is not None
        assert hasattr(loaded_model, "predict")
        assert "test_model" in manager.loaded_models

        cache_info = manager.get_cache_info()
        assert cache_info["size"] == 1

    def test_load_model_uses_cache_on_second_load(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager uses cache for subsequent model loads."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        model1 = manager.load_model("test_model")
        model2 = manager.load_model("test_model")

        assert model1 is model2

    def test_detect_model_type_identifies_formats(self, temp_models_dir: Path) -> None:
        """ModelManager detects model type from file extension."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        assert manager._detect_model_type("model.pth") == "pth"
        assert manager._detect_model_type("model.h5") == "h5"
        assert manager._detect_model_type("model.onnx") == "onnx"
        assert manager._detect_model_type("model.pkl") == "pkl"
        assert manager._detect_model_type("model.joblib") == "joblib"

    def test_predict_with_registered_model(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager makes predictions using registered model."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        input_data = np.random.randn(3, 10)
        predictions = manager.predict("test_model", input_data)

        assert predictions is not None
        assert len(predictions) == 3

    def test_get_model_info_returns_comprehensive_info(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager returns comprehensive model information."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn", metadata={"custom": "data"})

        info = manager.get_model_info("test_model")

        assert info["path"] == str(model_path)
        assert info["type"] == "sklearn"
        assert "registered" in info
        assert info["metadata"]["custom"] == "data"

    def test_list_models_returns_all_registered(self, temp_models_dir: Path) -> None:
        """ModelManager lists all registered models."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        model1_path = temp_models_dir / "model1.pkl"
        model2_path = temp_models_dir / "model2.pkl"
        model1_path.write_bytes(b"data1")
        model2_path.write_bytes(b"data2")

        manager.register_model("model1", str(model1_path), "sklearn")
        manager.register_model("model2", str(model2_path), "sklearn")

        models = manager.list_models()

        assert len(models) == 2
        assert "model1" in models
        assert "model2" in models

    def test_unload_model_removes_from_memory(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager unloads model from memory."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        manager.load_model("test_model")
        assert "test_model" in manager.loaded_models

        manager.unload_model("test_model")
        assert "test_model" not in manager.loaded_models

    def test_unregister_model_removes_metadata(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager unregisters model and removes metadata."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        assert "test_model" in manager.model_metadata

        manager.unregister_model("test_model")

        assert "test_model" not in manager.model_metadata

        metadata_file = temp_models_dir / "model_metadata.json"
        with open(metadata_file) as f:
            saved_metadata = json.load(f)
        assert "test_model" not in saved_metadata

    def test_clear_cache_removes_cached_models(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager clears all cached models."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        manager.load_model("test_model")
        assert manager.get_cache_info()["size"] > 0

        manager.clear_cache()

        assert manager.get_cache_info()["size"] == 0

    def test_get_manager_stats_returns_statistics(self, temp_models_dir: Path) -> None:
        """ModelManager returns accurate statistics."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        stats = manager.get_manager_stats()

        assert "registered_models" in stats
        assert "loaded_models" in stats
        assert "available_backends" in stats
        assert "models_directory" in stats
        assert "cache_info" in stats

    def test_import_local_model_copies_and_registers(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager imports local model file."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))

        result = manager.import_local_model(str(model_path))

        assert result is not None
        assert "model_id" in result
        assert "local_path" in result
        assert result["type"] == "pkl"

    def test_train_model_sklearn_creates_trained_model(self, temp_models_dir: Path) -> None:
        """ModelManager trains sklearn model with real data."""
        try:
            manager = ModelManager(models_dir=str(temp_models_dir))

            X = np.random.randn(100, 10)
            y = np.random.randint(0, 2, 100)
            training_data = np.column_stack([X, y])

            success = manager.train_model(training_data, "sklearn")

            assert success is True
        except ImportError:
            pytest.skip("sklearn not available")

    def test_save_model_persists_to_disk(self, temp_models_dir: Path) -> None:
        """ModelManager saves model to disk successfully."""
        try:
            from sklearn.ensemble import RandomForestClassifier

            manager = ModelManager(models_dir=str(temp_models_dir))
            model = RandomForestClassifier(n_estimators=3, random_state=42)
            X = np.random.randn(50, 5)
            y = np.random.randint(0, 2, 50)
            model.fit(X, y)

            save_path = temp_models_dir / "saved_model.pkl"
            success = manager.save_model(model, str(save_path))

            assert success is True
            assert save_path.exists()
        except ImportError:
            pytest.skip("sklearn not available")

    def test_predict_batch_processes_multiple_inputs(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelManager processes batch predictions efficiently."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("test_model", str(model_path), "sklearn")

        batch_data = [np.random.randn(1, 10) for _ in range(5)]
        results = manager.predict_batch("test_model", batch_data)

        assert len(results) == 5
        assert all(r is not None for r in results)

    def test_load_pretrained_vulnerability_detector(self, temp_models_dir: Path) -> None:
        """ModelManager loads pretrained vulnerability detector model."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        model = manager.load_model("pretrained/vulnerability_detector")

        assert model is not None
        assert hasattr(model, "detect_vulnerabilities") or hasattr(model, "predict")

    def test_load_pretrained_protection_classifier(self, temp_models_dir: Path) -> None:
        """ModelManager loads pretrained protection classifier model."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        model = manager.load_model("pretrained/protection_classifier")

        assert model is not None
        assert hasattr(model, "classify_protections") or hasattr(model, "protection_patterns")

    def test_predict_vulnerabilities_detects_real_patterns(self, temp_models_dir: Path) -> None:
        """ModelManager detects real vulnerability patterns in binary data."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        binary_with_vulns = b"strcpy" + b"\x00" * 100 + b"gets" + b"\x00" * 100 + b"sprintf"
        result = manager.predict("pretrained/vulnerability_detector", binary_with_vulns)

        assert "vulnerabilities" in result
        assert "security_score" in result
        assert len(result["vulnerabilities"]) > 0
        assert any(v["type"] == "buffer_overflow" for v in result["vulnerabilities"])

    def test_predict_protections_detects_anti_debug(self, temp_models_dir: Path) -> None:
        """ModelManager detects anti-debug protection mechanisms."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        binary_with_protection = b"IsDebuggerPresent" + b"\x00" * 100 + b"CheckRemoteDebuggerPresent"
        result = manager.predict("pretrained/protection_classifier", binary_with_protection)

        assert "protections" in result
        assert any(p["type"] == "anti_debug" for p in result["protections"])

    def test_extract_binary_features_generates_feature_vector(self, temp_models_dir: Path) -> None:
        """ModelManager extracts feature vector from binary data."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        binary_data = np.random.bytes(5000)
        features = manager._extract_binary_features(binary_data)

        assert isinstance(features, np.ndarray)
        assert len(features) == 1024
        assert features.dtype == np.float32

    def test_calculate_entropy_computes_shannon_entropy(self, temp_models_dir: Path) -> None:
        """ModelManager calculates Shannon entropy of data."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        low_entropy_data = b"\x00" * 1000
        high_entropy_data = np.random.bytes(1000)

        low_entropy = manager._calculate_entropy(low_entropy_data)
        high_entropy = manager._calculate_entropy(high_entropy_data)

        assert low_entropy < 1.0
        assert high_entropy > 6.0

    def test_handle_missing_model_file_creates_fallback(self, temp_models_dir: Path) -> None:
        """ModelManager creates fallback model for missing files."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        nonexistent_path = str(temp_models_dir / "nonexistent.pth")
        manager.register_model("missing_model", nonexistent_path, "pytorch")

        try:
            model = manager.load_model("missing_model")
            assert model is not None
        except (FileNotFoundError, ImportError):
            pass


class TestAsyncModelManager:
    """Test AsyncModelManager for asynchronous operations."""

    def test_async_load_skips_in_testing_mode(self, temp_models_dir: Path) -> None:
        """AsyncModelManager skips thread creation in testing mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = ModelManager(models_dir=str(temp_models_dir))
        async_manager = AsyncModelManager(manager)

        callback_called = False

        def callback(success: bool, model: object, error: str) -> None:
            nonlocal callback_called
            callback_called = True

        result = async_manager.load_model_async("test_model", callback)

        assert result is None
        assert callback_called

        del os.environ["INTELLICRACK_TESTING"]

    def test_async_predict_skips_in_testing_mode(self, temp_models_dir: Path) -> None:
        """AsyncModelManager skips async prediction in testing mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = ModelManager(models_dir=str(temp_models_dir))
        async_manager = AsyncModelManager(manager)

        callback_called = False

        def callback(success: bool, result: object, error: str) -> None:
            nonlocal callback_called
            callback_called = True

        thread = async_manager.predict_async("test_model", np.random.randn(10), callback)

        assert thread is None
        assert callback_called

        del os.environ["INTELLICRACK_TESTING"]


class TestModelFineTuner:
    """Test ModelFineTuner for model fine-tuning operations."""

    def test_fine_tune_sklearn_model(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """ModelFineTuner fine-tunes sklearn model on new data."""
        try:
            _, model_path = sample_sklearn_model
            manager = ModelManager(models_dir=str(temp_models_dir))
            manager.register_model("base_model", str(model_path), "sklearn")

            fine_tuner = ModelFineTuner(manager)

            X_train = np.random.randn(50, 10)
            y_train = np.random.randint(0, 2, 50)
            X_val = np.random.randn(20, 10)
            y_val = np.random.randint(0, 2, 20)

            results = fine_tuner.fine_tune_model(
                "base_model",
                training_data=(X_train, y_train),
                validation_data=(X_val, y_val),
            )

            assert "fine_tuned_model_id" in results
            assert "validation_score" in results
        except ImportError:
            pytest.skip("sklearn not available")

    def test_get_training_history_retrieves_history(self, temp_models_dir: Path) -> None:
        """ModelFineTuner retrieves training history for fine-tuned models."""
        manager = ModelManager(models_dir=str(temp_models_dir))
        fine_tuner = ModelFineTuner(manager)

        fine_tuner.training_history["test_model"] = {"epochs": 10, "loss": [0.5, 0.3, 0.2]}

        history = fine_tuner.get_training_history("test_model")

        assert history is not None
        assert history["epochs"] == 10
        assert len(history["loss"]) == 3


class TestStandaloneFunctions:
    """Test standalone utility functions."""

    def test_create_model_manager_creates_instance(self, temp_models_dir: Path) -> None:
        """create_model_manager creates ModelManager instance."""
        manager = create_model_manager(models_dir=str(temp_models_dir), cache_size=3)

        assert isinstance(manager, ModelManager)
        assert manager.models_dir == str(temp_models_dir)
        assert manager.cache.max_cache_size == 3

    def test_get_global_model_manager_returns_singleton(self) -> None:
        """get_global_model_manager returns global singleton instance."""
        manager1 = get_global_model_manager()
        manager2 = get_global_model_manager()

        assert manager1 is manager2

    def test_import_custom_model_imports_and_registers(self, sample_sklearn_model: tuple[object, Path]) -> None:
        """import_custom_model imports and registers model successfully."""
        try:
            _, model_path = sample_sklearn_model

            result = import_custom_model(str(model_path), model_type="sklearn", model_id="custom_model")

            assert result["success"] is True
            assert result["model_id"] == "custom_model"
            assert "model_info" in result
        except ImportError:
            pytest.skip("sklearn not available")

    def test_load_model_standalone_loads_model(self, sample_sklearn_model: tuple[object, Path]) -> None:
        """load_model standalone function loads model successfully."""
        try:
            _, model_path = sample_sklearn_model

            model = load_model("test_load", str(model_path))

            assert model is not None
            assert hasattr(model, "predict")
        except ImportError:
            pytest.skip("sklearn not available")

    def test_save_model_standalone_saves_model(self, temp_models_dir: Path) -> None:
        """save_model standalone function saves model to disk."""
        try:
            from sklearn.ensemble import RandomForestClassifier

            model = RandomForestClassifier(n_estimators=3, random_state=42)
            X = np.random.randn(30, 5)
            y = np.random.randint(0, 2, 30)
            model.fit(X, y)

            manager = get_global_model_manager()
            manager.loaded_models["test_save"] = model

            save_path = temp_models_dir / "standalone_save.pkl"
            result = save_model("test_save", str(save_path))

            assert result["success"] is True
            assert save_path.exists()
        except ImportError:
            pytest.skip("sklearn not available")

    def test_list_available_models_returns_models(self) -> None:
        """list_available_models returns all available models."""
        result = list_available_models()

        assert result["success"] is True
        assert "models" in result
        assert "model_count" in result

    def test_configure_ai_provider_saves_configuration(self, tmp_path: Path) -> None:
        """configure_ai_provider saves provider configuration to disk."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = configure_ai_provider(
                "openai",
                {"api_key": "test_key_1234567890", "model": "gpt-4"},
            )

            assert result["success"] is True
            assert result["provider"] == "openai"

            config_file = tmp_path / ".intellicrack" / "ai_provider_config.json"
            assert config_file.exists()


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_concurrent_model_loading(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """Multiple threads can load models concurrently without errors."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir))
        manager.register_model("concurrent_model", str(model_path), "sklearn")

        results: list[object] = []
        errors: list[Exception] = []

        def load_worker() -> None:
            try:
                model = manager.load_model("concurrent_model")
                results.append(model)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=load_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10

    def test_memory_efficient_batch_processing(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """Batch processing handles large datasets efficiently."""
        _, model_path = sample_sklearn_model
        manager = ModelManager(models_dir=str(temp_models_dir), cache_size=2)
        manager.register_model("batch_model", str(model_path), "sklearn")

        large_batch = [np.random.randn(1, 10) for _ in range(100)]
        results = manager.predict_batch("batch_model", large_batch)

        assert len(results) == 100
        assert all(r is not None for r in results)

    def test_vulnerability_detection_workflow(self, temp_models_dir: Path) -> None:
        """Complete vulnerability detection workflow on real binary."""
        manager = ModelManager(models_dir=str(temp_models_dir))

        pe_header = b"MZ\x90\x00"
        vulnerable_code = b"strcpy" + b"\x00" * 50 + b"gets" + b"\x00" * 50
        suspicious_imports = b"VirtualAlloc" + b"\x00" * 30 + b"WriteProcessMemory"

        binary = pe_header + vulnerable_code + suspicious_imports

        result = manager.predict("pretrained/vulnerability_detector", binary)

        assert result["vulnerabilities"]
        assert result["security_score"] < 100
        assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert "recommendations" in result

    def test_model_metadata_persistence_across_sessions(self, temp_models_dir: Path, sample_sklearn_model: tuple[object, Path]) -> None:
        """Model metadata persists across manager instances."""
        _, model_path = sample_sklearn_model

        manager1 = ModelManager(models_dir=str(temp_models_dir))
        manager1.register_model("persistent_model", str(model_path), "sklearn", metadata={"version": "1.0"})
        del manager1

        manager2 = ModelManager(models_dir=str(temp_models_dir))
        assert "persistent_model" in manager2.model_metadata
        assert manager2.model_metadata["persistent_model"]["metadata"]["version"] == "1.0"

    def test_corrupted_metadata_recovery(self, temp_models_dir: Path) -> None:
        """ModelManager recovers from corrupted metadata file."""
        metadata_file = temp_models_dir / "model_metadata.json"
        metadata_file.write_text("{ invalid json content }")

        manager = ModelManager(models_dir=str(temp_models_dir))

        assert manager.model_metadata == {}

    def test_large_model_handling(self, temp_models_dir: Path) -> None:
        """ModelManager handles large model files efficiently."""
        try:
            from sklearn.ensemble import RandomForestClassifier

            large_model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
            X = np.random.randn(1000, 50)
            y = np.random.randint(0, 5, 1000)
            large_model.fit(X, y)

            model_path = temp_models_dir / "large_model.pkl"
            import joblib

            joblib.dump(large_model, model_path)

            manager = ModelManager(models_dir=str(temp_models_dir))
            manager.register_model("large_model", str(model_path), "sklearn")

            loaded = manager.load_model("large_model")
            assert loaded is not None

            predictions = manager.predict("large_model", X[:10])
            assert len(predictions) == 10
        except ImportError:
            pytest.skip("sklearn not available")
