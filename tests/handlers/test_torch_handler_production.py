"""Production-grade tests for PyTorch handler.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def simulate_intel_arc() -> Generator[None, None, None]:
    old_value = os.environ.get("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS")
    os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = "1"
    yield
    if old_value is not None:
        os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = old_value
    else:
        os.environ.pop("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS", None)


class TestTorchHandlerFallbackMode:
    """Test PyTorch handler fallback tensor operations."""

    def test_fallback_tensor_creation(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            tensor_obj = handler.tensor([1, 2, 3, 4])

            assert tensor_obj is not None
            assert tensor_obj.data == [1, 2, 3, 4]

    def test_fallback_tensor_cuda_operations(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            tensor_obj = handler.tensor([1.0, 2.0, 3.0])

            cuda_tensor = tensor_obj.cuda()
            assert cuda_tensor is not None

            cpu_tensor = cuda_tensor.cpu()
            assert cpu_tensor is not None

    def test_fallback_cuda_availability(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            assert not handler.cuda.is_available()
            assert handler.cuda.device_count() == 0
            assert handler.cuda.get_device_name() == "CPU Fallback"

    def test_fallback_device_creation(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            device_obj = handler.device("cpu")

            assert device_obj is not None
            assert device_obj.type == "cpu"

    def test_fallback_tensor_numpy_conversion(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            tensor_obj = handler.tensor([5, 6, 7, 8])
            numpy_array = tensor_obj.numpy()

            assert numpy_array == [5, 6, 7, 8]

    def test_fallback_save_and_load_operations(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if not handler.HAS_TORCH:
            test_obj = {"model_state": [1, 2, 3]}

            handler.save(test_obj, "test_model.pth")

            loaded = handler.load("test_model.pth")
            assert loaded == {}

    def test_intel_arc_detection_and_workaround(self, simulate_intel_arc: None) -> None:
        import importlib

        import intellicrack.handlers.torch_handler as handler

        importlib.reload(handler)

        assert handler._is_intel_arc
        assert not handler.HAS_TORCH


class TestTorchHandlerRealMode:
    """Test PyTorch handler with real PyTorch (if available)."""

    def test_real_torch_detection(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if handler.HAS_TORCH:
            assert handler.TORCH_VERSION is not None
            assert handler.torch is not None
            assert handler.Tensor is not None

    def test_torch_cuda_availability_detection(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        if handler.HAS_TORCH:
            cuda_available = handler.cuda.is_available()
            assert isinstance(cuda_available, bool)

    def test_all_torch_components_available(self) -> None:
        import intellicrack.handlers.torch_handler as handler

        assert handler.tensor is not None
        assert handler.device is not None
        assert handler.save is not None
        assert handler.load is not None
