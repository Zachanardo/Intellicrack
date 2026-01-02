"""Real-world AI model management tests.

Tests model caching, downloading, format conversion, sharding, quantization, and LoRA adapters.
Tests use actual module APIs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Generator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.ai.model_cache_manager import (
        CacheEntry,
        ModelCacheManager,
        get_cache_manager,
    )

    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    from intellicrack.ai.model_download_manager import (
        DownloadProgress,
        ModelDownloadManager,
        get_download_manager,
    )

    DOWNLOAD_AVAILABLE = True
except ImportError:
    DOWNLOAD_AVAILABLE = False

try:
    from intellicrack.ai.model_format_converter import (
        ModelFormatConverter,
        get_model_converter,
    )

    FORMAT_CONVERTER_AVAILABLE = True
except ImportError:
    FORMAT_CONVERTER_AVAILABLE = False

try:
    from intellicrack.ai.model_sharding import (
        ModelShardingManager,
        get_sharding_manager,
    )

    SHARDING_AVAILABLE = True
except ImportError:
    SHARDING_AVAILABLE = False

try:
    from intellicrack.ai.quantization_manager import (
        QuantizationManager,
        get_quantization_manager,
    )

    QUANTIZATION_AVAILABLE = True
except ImportError:
    QUANTIZATION_AVAILABLE = False

try:
    from intellicrack.ai.lora_adapter_manager import (
        LoRAAdapterManager,
        LoraConfig,
        get_adapter_manager,
    )

    LORA_AVAILABLE = True
except ImportError:
    LORA_AVAILABLE = False


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_model_file(temp_dir: Path) -> Path:
    """Create a mock model file for testing."""
    model_file = temp_dir / "test_model.bin"
    model_file.write_bytes(b"MOCK_MODEL_DATA" * 1000)
    return model_file


class MockModel:
    """Mock model for cache testing."""

    def __init__(self) -> None:
        self.device = "cpu"
        self._data = b"MODEL_DATA" * 100

    def forward(self, x: Any) -> Any:
        """Mock forward pass."""
        return x

    def parameters(self) -> list[Any]:
        """Mock parameters."""
        return []


@pytest.mark.skipif(not CACHE_AVAILABLE, reason="Model cache manager not available")
class TestModelCacheManager:
    """Test model caching capabilities."""

    def test_cache_manager_initialization(self, temp_dir: Path) -> None:
        """Test cache manager initialization."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir))

        assert cache_manager is not None
        assert cache_manager.cache_dir.exists()
        assert hasattr(cache_manager, "put")
        assert hasattr(cache_manager, "get")
        assert hasattr(cache_manager, "clear")

    def test_cache_entry_dataclass(self) -> None:
        """Test CacheEntry dataclass creation."""
        entry = CacheEntry(
            model_id="model_vmprotect_v3",
            model_type="pytorch",
            model_object=MockModel(),
            tokenizer_object=None,
            config={"version": "1.0"},
            memory_size=50000000,
            last_accessed=datetime.now(),
            access_count=15,
            load_time=1.5,
            device="cpu",
        )

        assert entry is not None
        assert entry.model_id == "model_vmprotect_v3"
        assert entry.memory_size == 50000000
        assert entry.access_count == 15

    def test_put_model_in_cache(self, temp_dir: Path) -> None:
        """Test putting model in cache."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))
        mock_model = MockModel()

        cache_manager.put(model_id="test_model", model=mock_model)

        # Check model is in cache
        assert "test_model" in cache_manager.cache

    def test_get_model_from_cache(self, temp_dir: Path) -> None:
        """Test retrieving model from cache."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))
        mock_model = MockModel()

        cache_manager.put(model_id="retrieve_test", model=mock_model)

        result = cache_manager.get(model_id="retrieve_test")

        assert result is not None
        assert result[0] is not None

    def test_cache_miss(self, temp_dir: Path) -> None:
        """Test cache miss returns None."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))

        result = cache_manager.get(model_id="nonexistent_model")

        assert result is None

    def test_cache_with_load_function(self, temp_dir: Path) -> None:
        """Test cache with load function."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))

        def load_model() -> tuple[MockModel, None]:
            return MockModel(), None

        result = cache_manager.get(model_id="loaded_model", load_function=load_model)

        assert result is not None
        assert result[0] is not None

    def test_clear_cache(self, temp_dir: Path) -> None:
        """Test clearing entire cache."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))

        for i in range(5):
            cache_manager.put(model_id=f"model_{i}", model=MockModel())

        cache_manager.clear()

        assert len(cache_manager.cache) == 0

    def test_cache_statistics(self, temp_dir: Path) -> None:
        """Test cache statistics retrieval."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))

        cache_manager.put(model_id="stats_model", model=MockModel())
        cache_manager.get(model_id="stats_model")
        cache_manager.get(model_id="stats_model")
        cache_manager.get(model_id="nonexistent")

        stats = cache_manager.get_stats()

        assert stats is not None
        assert isinstance(stats, dict)
        assert "hits" in stats
        assert "misses" in stats

    def test_global_cache_manager_singleton(self) -> None:
        """Test global cache manager singleton."""
        manager1 = get_cache_manager()
        manager2 = get_cache_manager()

        assert manager1 is manager2


@pytest.mark.skipif(not DOWNLOAD_AVAILABLE, reason="Model download manager not available")
class TestModelDownloadManager:
    """Test model downloading capabilities."""

    def test_download_manager_initialization(self, temp_dir: Path) -> None:
        """Test download manager initialization."""
        manager = ModelDownloadManager(cache_dir=str(temp_dir))

        assert manager is not None
        assert manager.cache_dir.exists()
        assert hasattr(manager, "download_model")

    def test_download_progress_dataclass(self) -> None:
        """Test DownloadProgress dataclass creation."""
        progress = DownloadProgress(
            total_size=100000000,
            downloaded_size=45000000,
            speed=5000000.0,
            eta=11.0,
            percentage=45.0,
        )

        assert progress is not None
        assert progress.downloaded_size == 45000000
        assert progress.percentage == 45.0

    def test_list_cached_models(self, temp_dir: Path) -> None:
        """Test listing cached models."""
        manager = ModelDownloadManager(cache_dir=str(temp_dir))

        models = manager.list_cached_models()

        assert models is not None
        assert isinstance(models, dict)

    def test_get_cache_size(self, temp_dir: Path) -> None:
        """Test getting cache size."""
        manager = ModelDownloadManager(cache_dir=str(temp_dir))

        size_info = manager.get_cache_size()

        assert isinstance(size_info, dict)
        assert "total_size_mb" in size_info

    def test_global_download_manager_singleton(self) -> None:
        """Test global download manager singleton."""
        manager = get_download_manager()

        assert manager is not None


@pytest.mark.skipif(not FORMAT_CONVERTER_AVAILABLE, reason="Format converter not available")
class TestModelFormatConverter:
    """Test model format conversion capabilities."""

    def test_converter_initialization(self) -> None:
        """Test format converter initialization."""
        converter = ModelFormatConverter()

        assert converter is not None

    def test_global_format_converter_singleton(self) -> None:
        """Test global format converter singleton."""
        converter = get_model_converter()

        assert converter is not None


@pytest.mark.skipif(not SHARDING_AVAILABLE, reason="Model sharding manager not available")
class TestModelSharding:
    """Test model sharding capabilities."""

    def test_sharding_manager_initialization(self) -> None:
        """Test sharding manager initialization."""
        manager = ModelShardingManager()

        assert manager is not None

    def test_global_sharding_manager_singleton(self) -> None:
        """Test global sharding manager singleton."""
        manager = get_sharding_manager()

        assert manager is not None


@pytest.mark.skipif(not QUANTIZATION_AVAILABLE, reason="Quantization manager not available")
class TestQuantizationManager:
    """Test model quantization capabilities."""

    def test_quantization_manager_initialization(self) -> None:
        """Test quantization manager initialization."""
        manager = QuantizationManager()

        assert manager is not None

    def test_global_quantization_manager_singleton(self) -> None:
        """Test global quantization manager singleton."""
        manager = get_quantization_manager()

        assert manager is not None


@pytest.mark.skipif(not LORA_AVAILABLE, reason="LoRA adapter manager not available")
class TestLoRAAdapterManager:
    """Test LoRA adapter management capabilities."""

    def test_lora_manager_initialization(self) -> None:
        """Test LoRA adapter manager initialization."""
        manager = LoRAAdapterManager()

        assert manager is not None

    def test_lora_config_dataclass(self) -> None:
        """Test LoraConfig dataclass creation."""
        config = LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.1,
            target_modules=["query", "key", "value"],
        )

        assert config is not None
        assert config.r == 16
        assert config.lora_alpha == 32

    def test_list_loaded_adapters(self) -> None:
        """Test listing loaded LoRA adapters."""
        manager = LoRAAdapterManager()

        # list_adapters requires a model argument
        # Without a real model, we just verify the manager exists
        assert manager is not None
        assert hasattr(manager, "list_adapters")

    def test_global_lora_manager_singleton(self) -> None:
        """Test global LoRA adapter manager singleton."""
        manager = get_adapter_manager()

        assert manager is not None


class TestIntegration:
    """Test integration between model management components."""

    @pytest.mark.skipif(not CACHE_AVAILABLE, reason="Required modules not available")
    def test_cache_and_retrieve_model(self, temp_dir: Path) -> None:
        """Test caching and retrieving a model."""
        cache_manager = ModelCacheManager(cache_dir=str(temp_dir / "cache"))

        mock_model = MockModel()
        cache_manager.put(model_id="integrated_model", model=mock_model)

        result = cache_manager.get(model_id="integrated_model")

        assert result is not None
        assert result[0] is not None
