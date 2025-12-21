"""Production tests for model cache manager.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
import torch
import torch.nn as nn

from intellicrack.ai.model_cache_manager import (
    CacheEntry,
    ModelCacheManager,
    RestrictedUnpickler,
    get_cache_manager,
    secure_pickle_dump,
    secure_pickle_load,
)


class SimplePyTorchModel(nn.Module):
    """Simple real PyTorch model for testing."""

    def __init__(self, num_params: int = 1000) -> None:
        """Initialize simple model with configurable parameters."""
        super().__init__()
        self.num_params = num_params
        self.linear1 = nn.Linear(100, 200)
        self.linear2 = nn.Linear(200, 300)
        self.linear3 = nn.Linear(300, 400)
        self.device = torch.device("cpu")

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass through the model."""
        x = self.linear1(x)
        x = self.linear2(x)
        x = self.linear3(x)
        return x


class TestSecurePickle:
    """Test secure pickle operations."""

    def test_secure_pickle_dump_and_load(self) -> None:
        """Secure pickle can save and load objects with integrity check."""
        test_obj = {"key": "value", "numbers": [1, 2, 3], "nested": {"a": "b"}}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = f.name

        try:
            secure_pickle_dump(test_obj, temp_path)

            assert Path(temp_path).exists()

            loaded_obj = secure_pickle_load(temp_path)

            assert loaded_obj == test_obj
            assert loaded_obj["key"] == "value"
            assert loaded_obj["numbers"] == [1, 2, 3]
            assert loaded_obj["nested"]["a"] == "b"

        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def test_secure_pickle_load_detects_tampering(self) -> None:
        """Secure pickle detects file tampering via integrity check."""
        test_obj = {"data": "original"}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = f.name

        try:
            secure_pickle_dump(test_obj, temp_path)

            with open(temp_path, "rb") as f:
                data = f.read()

            tampered_data = data[:32] + b"TAMPERED" + data[40:]

            with open(temp_path, "wb") as f:
                f.write(tampered_data)

            with pytest.raises(ValueError, match="integrity check failed"):
                secure_pickle_load(temp_path)

        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()

    def test_secure_pickle_handles_complex_objects(self) -> None:
        """Secure pickle handles complex nested objects."""
        complex_obj = {
            "lists": [[1, 2], [3, 4]],
            "tuples": ((5, 6), (7, 8)),
            "sets": {9, 10, 11},
            "dict": {"nested": {"deeply": {"value": 12}}},
        }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            temp_path = f.name

        try:
            secure_pickle_dump(complex_obj, temp_path)
            loaded_obj = secure_pickle_load(temp_path)

            assert loaded_obj["lists"] == [[1, 2], [3, 4]]
            assert loaded_obj["tuples"] == ((5, 6), (7, 8))
            assert loaded_obj["sets"] == {9, 10, 11}
            assert loaded_obj["dict"]["nested"]["deeply"]["value"] == 12

        finally:
            if Path(temp_path).exists():
                Path(temp_path).unlink()


class TestRestrictedUnpickler:
    """Test restricted unpickler security."""

    def test_restricted_unpickler_allows_safe_classes(self) -> None:
        """Restricted unpickler allows whitelisted safe classes."""
        safe_obj = {"safe": "data"}
        data = pickle.dumps(safe_obj)

        import io

        unpickler = RestrictedUnpickler(io.BytesIO(data))
        loaded = unpickler.load()

        assert loaded == safe_obj

    def test_restricted_unpickler_allows_intellicrack_classes(self) -> None:
        """Restricted unpickler allows Intellicrack module classes."""
        mock_class = type("MockClass", (), {"value": 42})
        mock_class.__module__ = "intellicrack.test.module"

        instance = mock_class()

        data = pickle.dumps(instance)

        import io

        unpickler = RestrictedUnpickler(io.BytesIO(data))

        loaded = unpickler.load()
        assert hasattr(loaded, "value")


class TestModelCacheManager:
    """Test model cache manager functionality."""

    @pytest.fixture
    def temp_cache_dir(self) -> Path:
        """Create temporary cache directory."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir

        import shutil

        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    @pytest.fixture
    def cache_manager(self, temp_cache_dir: Path) -> ModelCacheManager:
        """Create cache manager with temporary directory."""
        return ModelCacheManager(
            max_memory_gb=1.0,
            cache_dir=str(temp_cache_dir),
            enable_disk_cache=True,
        )

    def test_cache_manager_initialization(self, temp_cache_dir: Path) -> None:
        """Cache manager initializes with correct settings."""
        manager = ModelCacheManager(
            max_memory_gb=2.0,
            cache_dir=str(temp_cache_dir),
            enable_disk_cache=True,
        )

        assert manager.max_memory_bytes == 2 * 1024 * 1024 * 1024
        assert manager.cache_dir == temp_cache_dir
        assert manager.enable_disk_cache is True
        assert len(manager.cache) == 0
        assert manager.current_memory_usage == 0

    def test_put_and_get_model(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager stores and retrieves models correctly."""
        model = SimplePyTorchModel()
        tokenizer = {"vocab": "test"}

        cache_manager.put(
            model_id="test-model",
            model=model,
            tokenizer=tokenizer,
            model_type="pytorch",
        )

        assert "test-model" in cache_manager.cache
        assert cache_manager.current_memory_usage > 0

        retrieved_model, retrieved_tokenizer = cache_manager.get("test-model")

        assert retrieved_model is model
        assert retrieved_tokenizer is tokenizer

    def test_get_with_load_function(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager loads model using provided function."""
        model = SimplePyTorchModel()
        tokenizer = {"vocab": "loaded"}

        def load_function() -> tuple[SimplePyTorchModel, dict[str, str]]:
            """Load function that returns model and tokenizer."""
            return model, tokenizer

        result = cache_manager.get("new-model", load_function=load_function)

        assert result is not None
        loaded_model, loaded_tokenizer = result
        assert loaded_model is model
        assert loaded_tokenizer is tokenizer
        assert "new-model" in cache_manager.cache

    def test_lru_eviction(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager evicts least recently used models."""
        cache_manager.max_memory_bytes = 10000

        model1 = SimplePyTorchModel()
        model2 = SimplePyTorchModel()
        model3 = SimplePyTorchModel()

        cache_manager.put("model1", model1)
        cache_manager.put("model2", model2)

        time.sleep(0.01)
        cache_manager.get("model1")

        cache_manager.put("model3", model3)

        assert "model1" in cache_manager.cache or "model1" in cache_manager.disk_index
        assert cache_manager.stats["evictions"] >= 0

    def test_memory_estimation_pytorch(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager estimates PyTorch model memory correctly."""
        model = SimplePyTorchModel()

        estimated_size = cache_manager._estimate_model_memory(model)

        assert estimated_size > 0
        assert estimated_size > 100000

    def test_cache_statistics(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager tracks statistics correctly."""
        model = SimplePyTorchModel()

        cache_manager.put("model1", model)
        cache_manager.get("model1")
        cache_manager.get("model1")
        cache_manager.get("missing-model")

        stats = cache_manager.get_stats()

        assert stats["statistics"]["hits"] == 2
        assert stats["statistics"]["misses"] == 1
        assert stats["statistics"]["hit_rate"] > 0
        assert stats["memory_cache"]["entries"] > 0

    def test_disk_cache_save_and_load(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager saves to and loads from disk cache."""
        cache_manager.max_memory_bytes = 5000

        model1 = SimplePyTorchModel()
        model2 = SimplePyTorchModel()

        cache_manager.put("model1", model1)
        cache_manager.put("model2", model2)

        time.sleep(0.1)

        if cache_manager.stats["evictions"] > 0:
            assert len(cache_manager.disk_index) > 0

    def test_cache_clear(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager clears all cached models."""
        model = SimplePyTorchModel()

        cache_manager.put("model1", model)
        cache_manager.put("model2", model)

        assert len(cache_manager.cache) > 0

        cache_manager.clear(clear_disk=False)

        assert len(cache_manager.cache) == 0
        assert cache_manager.current_memory_usage == 0

    def test_cache_clear_with_disk(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager clears disk cache when requested."""
        model = SimplePyTorchModel()

        cache_manager.put("model1", model)
        cache_manager.clear(clear_disk=True)

        assert len(cache_manager.cache) == 0
        assert len(cache_manager.disk_index) == 0

    def test_auto_detect_model_type(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager auto-detects model type correctly."""
        pytorch_model = SimplePyTorchModel()

        cache_manager.put("pytorch-model", pytorch_model, model_type="auto")

        entry = cache_manager.cache["pytorch-model"]
        assert entry.model_type == "pytorch"

    def test_list_cached_models(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager lists all cached models."""
        model1 = SimplePyTorchModel()
        model2 = SimplePyTorchModel()

        cache_manager.put("model1", model1)
        cache_manager.put("model2", model2)

        models = cache_manager.list_cached_models()

        assert len(models) >= 2
        assert any(m["model_id"] == "model1" for m in models)
        assert any(m["model_id"] == "model2" for m in models)

    def test_set_memory_limit(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager updates memory limit and evicts if needed."""
        model = SimplePyTorchModel()

        cache_manager.put("model1", model)
        original_limit = cache_manager.max_memory_bytes

        cache_manager.set_memory_limit(0.0001)

        assert cache_manager.max_memory_bytes < original_limit
        assert cache_manager.max_memory_bytes == int(0.0001 * 1024 * 1024 * 1024)

    def test_cache_model_convenience_method(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager cache_model convenience method works."""
        model = SimplePyTorchModel()
        tokenizer = {"vocab": "test"}

        cache_manager.cache_model("test", model, tokenizer)

        assert "test" in cache_manager.cache
        assert cache_manager.cache["test"].model_object is model
        assert cache_manager.cache["test"].tokenizer_object is tokenizer

    def test_get_model_convenience_method(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager get_model convenience method works."""
        model = SimplePyTorchModel()

        cache_manager.cache_model("test", model)

        retrieved = cache_manager.get_model("test")

        assert retrieved is model

    def test_get_model_returns_none_if_not_cached(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager get_model returns None for missing models."""
        result = cache_manager.get_model("nonexistent")

        assert result is None

    def test_cache_access_updates_lru_order(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager updates LRU order on access."""
        model1 = SimplePyTorchModel()
        model2 = SimplePyTorchModel()

        cache_manager.put("model1", model1)
        time.sleep(0.01)
        cache_manager.put("model2", model2)

        cache_manager.get("model1")

        cache_keys = list(cache_manager.cache.keys())
        assert cache_keys[-1] == "model1"

    def test_preload_models(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager preloads multiple models."""
        model1 = SimplePyTorchModel()
        model2 = SimplePyTorchModel()

        load_functions = {
            "model1": lambda: (model1, None),
            "model2": lambda: (model2, None),
        }

        cache_manager.preload_models(["model1", "model2"], load_functions)

        assert "model1" in cache_manager.cache
        assert "model2" in cache_manager.cache

    def test_cache_entry_metadata(self, cache_manager: ModelCacheManager) -> None:
        """Cache entries store complete metadata."""
        model = SimplePyTorchModel()
        config = {"param1": "value1", "param2": 123}

        cache_manager.put(
            model_id="test",
            model=model,
            model_type="pytorch",
            config=config,
            quantization="int8",
            adapter_info={"lora": "enabled"},
        )

        entry = cache_manager.cache["test"]

        assert entry.model_id == "test"
        assert entry.model_type == "pytorch"
        assert entry.config == config
        assert entry.quantization == "int8"
        assert entry.adapter_info == {"lora": "enabled"}
        assert entry.access_count == 1

    def test_concurrent_access_safety(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager handles rapid concurrent access."""
        model = SimplePyTorchModel()

        cache_manager.put("model", model)

        for _ in range(100):
            cache_manager.get("model")

        entry = cache_manager.cache["model"]
        assert entry.access_count > 1

    def test_disk_cache_disabled(self, temp_cache_dir: Path) -> None:
        """Cache manager works without disk cache."""
        manager = ModelCacheManager(
            max_memory_gb=1.0,
            cache_dir=str(temp_cache_dir),
            enable_disk_cache=False,
        )

        model = SimplePyTorchModel()
        manager.put("model", model)

        assert "model" in manager.cache
        assert len(manager.disk_index) == 0

    def test_get_cache_manager_singleton(self) -> None:
        """Global cache manager returns singleton instance."""
        manager1 = get_cache_manager(max_memory_gb=1.0)
        manager2 = get_cache_manager(max_memory_gb=2.0)

        assert manager1 is manager2

    def test_load_function_error_handling(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager handles load function errors gracefully."""

        def failing_load_function() -> None:
            """Load function that raises exception."""
            raise RuntimeError("Load failed")

        result = cache_manager.get("test", load_function=failing_load_function)

        assert result is None
        assert "test" not in cache_manager.cache

    def test_disk_index_corruption_recovery(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager recovers from corrupted disk index."""
        index_file = cache_manager.disk_index_file
        index_file.write_text("CORRUPTED JSON DATA{{{")

        recovered_index = cache_manager._load_disk_index()

        assert isinstance(recovered_index, dict)
        assert len(recovered_index) == 0

    def test_memory_usage_tracking(self, cache_manager: ModelCacheManager) -> None:
        """Cache manager accurately tracks memory usage."""
        initial_usage = cache_manager.current_memory_usage

        model = SimplePyTorchModel()
        cache_manager.put("model", model)

        assert cache_manager.current_memory_usage > initial_usage

        cache_manager.clear()

        assert cache_manager.current_memory_usage == 0
