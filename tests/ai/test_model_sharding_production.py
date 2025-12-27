"""Production tests for model sharding and distribution.

Tests real distributed model loading, device mapping, and GPU sharding.
"""

import pytest

from intellicrack.ai.model_sharding import (
    HAS_ACCELERATE,
    HAS_TORCH,
    ModelShardingManager,
    get_sharding_manager,
)


pytestmark = pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not available")


@pytest.fixture
def sharding_manager() -> ModelShardingManager:
    """Create model sharding manager."""
    return ModelShardingManager()


def test_sharding_manager_initialization(sharding_manager: ModelShardingManager) -> None:
    """Test sharding manager initializes correctly."""
    assert sharding_manager is not None
    assert hasattr(sharding_manager, "available_devices")


def test_get_available_devices(sharding_manager: ModelShardingManager) -> None:
    """Test device detection."""
    devices = sharding_manager.get_available_devices()

    assert isinstance(devices, list)
    assert len(devices) >= 1
    assert "cpu" in [str(d) for d in devices]


def test_get_device_memory(sharding_manager: ModelShardingManager) -> None:
    """Test device memory reporting."""
    devices = sharding_manager.get_available_devices()

    for device in devices:
        memory = sharding_manager.get_device_memory(device)
        assert isinstance(memory, dict)
        assert "total" in memory or "available" in memory


@pytest.mark.skipif(not HAS_ACCELERATE, reason="Accelerate not available")
def test_infer_device_map() -> None:
    """Test device map inference for model distribution."""
    import torch.nn as nn

    manager = ModelShardingManager()

    class SimpleModel(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.layer1 = nn.Linear(100, 100)
            self.layer2 = nn.Linear(100, 100)

        def forward(self, x):
            return self.layer2(self.layer1(x))

    model = SimpleModel()

    device_map = manager.infer_auto_device_map(model, max_memory_per_gpu=1024)

    assert isinstance(device_map, dict)


def test_get_sharding_manager_singleton() -> None:
    """Test singleton pattern."""
    manager1 = get_sharding_manager()
    manager2 = get_sharding_manager()

    assert manager1 is manager2


def test_device_balance_scoring(sharding_manager: ModelShardingManager) -> None:
    """Test device balance score calculation."""
    device_map = {"layer1": "cuda:0", "layer2": "cuda:1", "layer3": "cpu"}

    score = sharding_manager.calculate_balance_score(device_map)

    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_multi_gpu_detection(sharding_manager: ModelShardingManager) -> None:
    """Test multi-GPU detection."""
    gpu_count = sharding_manager.get_gpu_count()

    assert isinstance(gpu_count, int)
    assert gpu_count >= 0
