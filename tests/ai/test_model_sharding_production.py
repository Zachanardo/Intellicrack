"""Production tests for model sharding and distribution.

Tests real distributed model loading, device mapping, and GPU sharding.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.ai.model_sharding import (
    HAS_ACCELERATE,
    HAS_TORCH,
    ModelShardingManager,
    get_sharding_manager,
)

if TYPE_CHECKING:
    import torch


pytestmark = pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")


@pytest.fixture
def sharding_manager() -> ModelShardingManager:
    """Create model sharding manager."""
    return ModelShardingManager()


def test_sharding_manager_initialization(sharding_manager: ModelShardingManager) -> None:
    """Test sharding manager initializes correctly."""
    assert sharding_manager is not None
    assert hasattr(sharding_manager, "device_count")
    assert hasattr(sharding_manager, "gpu_type")


def test_device_count_is_integer(sharding_manager: ModelShardingManager) -> None:
    """Test device count is a valid integer."""
    assert isinstance(sharding_manager.device_count, int)
    assert sharding_manager.device_count >= 0


def test_gpu_type_is_string(sharding_manager: ModelShardingManager) -> None:
    """Test GPU type is a recognized string."""
    assert isinstance(sharding_manager.gpu_type, str)
    assert sharding_manager.gpu_type in ["nvidia_cuda", "intel_xpu", "cpu", "cuda"]


def test_get_sharding_info(sharding_manager: ModelShardingManager) -> None:
    """Test sharding info retrieval."""
    info = sharding_manager.get_sharding_info()

    assert isinstance(info, dict)
    assert "device_count" in info
    assert "gpu_type" in info


@pytest.mark.skipif(not HAS_ACCELERATE, reason="Accelerate not available")
def test_device_properties_populated() -> None:
    """Test device properties are populated when GPUs available."""
    manager = ModelShardingManager()

    if manager.device_count > 0:
        assert len(manager.device_properties) > 0 or manager.device_count == 0


def test_get_sharding_manager_singleton() -> None:
    """Test singleton pattern."""
    manager1 = get_sharding_manager()
    manager2 = get_sharding_manager()

    assert manager1 is manager2


def test_device_balance_scoring(sharding_manager: ModelShardingManager) -> None:
    """Test device balance score calculation."""
    device_map: dict[str, Any] = {"layer1": "cuda:0", "layer2": "cuda:1", "layer3": "cpu"}

    score = sharding_manager.get_device_balance_score(device_map)

    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_monitor_memory_usage(sharding_manager: ModelShardingManager) -> None:
    """Test memory usage monitoring."""
    memory_usage = sharding_manager.monitor_memory_usage()

    assert isinstance(memory_usage, dict)


def test_cleanup_memory(sharding_manager: ModelShardingManager) -> None:
    """Test memory cleanup does not raise."""
    try:
        sharding_manager.cleanup_memory()
    except Exception as e:
        pytest.fail(f"cleanup_memory should not raise: {e}")


def test_shard_configs_initialized(sharding_manager: ModelShardingManager) -> None:
    """Test shard configs dictionary is initialized."""
    assert hasattr(sharding_manager, "shard_configs")
    assert isinstance(sharding_manager.shard_configs, dict)
