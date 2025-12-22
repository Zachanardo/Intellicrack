"""GPU Integration Module for AI Components.

This module provides GPU integration for AI components using the unified GPU autoloader system.

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

import logging
from typing import Any, Protocol


logger = logging.getLogger(__name__)


class GPUAutoLoaderProtocol(Protocol):
    """Protocol for GPU autoloader interface."""

    def get_memory_info(self) -> dict[str, object]:
        """Get memory info."""
        ...

    def synchronize(self) -> None:
        """Synchronize GPU operations."""
        ...


# Declare the gpu_autoloader_instance variable
_gpu_autoloader_instance: GPUAutoLoaderProtocol

# Import unified GPU system
try:
    from ..utils.gpu_autoloader import (
        GPUAutoLoader,
        get_device,
        get_gpu_info,
        gpu_autoloader,
        optimize_for_gpu,
        to_device,
    )

    GPU_AUTOLOADER_AVAILABLE = True
    _gpu_autoloader_instance = gpu_autoloader
except ImportError:
    logger.warning("GPU autoloader not available, using fallback implementations")
    GPU_AUTOLOADER_AVAILABLE = False

    # Fallback implementations
    def get_device() -> Any:
        """Get the compute device (CPU when GPU not available).

        Returns:
            Any: CPU device instance or "cpu" string if torch unavailable.

        """
        from ..utils.torch_gil_safety import safe_torch_import

        torch = safe_torch_import()
        return "cpu" if torch is None else torch.device("cpu")

    def get_gpu_info() -> dict[str, object]:
        """Get GPU information (fallback to CPU info).

        Returns:
            dict[str, object]: Device info indicating CPU-only mode.

        """
        return {
            "available": False,
            "type": "cpu",
            "device": "cpu",
            "info": {},
            "memory": {},
        }

    def to_device(tensor_or_model: Any) -> Any:
        """Move tensor or model to device (no-op for CPU).

        Args:
            tensor_or_model: PyTorch tensor or model object.

        Returns:
            Any: Same tensor or model unchanged.

        """
        return tensor_or_model

    def optimize_for_gpu(model: Any) -> Any:
        """Optimize model for GPU (no-op for CPU).

        Args:
            model: PyTorch model object.

        Returns:
            Any: Same model unchanged.

        """
        return model

    class _FallbackGPUAutoloader:
        """Fallback GPU autoloader when real one is unavailable."""

        def get_memory_info(self) -> dict[str, object]:
            """Get memory info (fallback returns empty dict)."""
            return {}

        def synchronize(self) -> None:
            """Synchronize GPU operations (no-op for CPU)."""
            pass

    _gpu_autoloader_instance = _FallbackGPUAutoloader()


class GPUIntegration:
    """GPU Integration for AI models using unified system."""

    def __init__(self) -> None:
        """Initialize GPU integration."""
        self.gpu_info = get_gpu_info()
        self.device = get_device()
        logger.info("GPU Integration initialized: %s", self.gpu_info["type"])

    def get_device_info(self) -> dict[str, Any]:
        """Get comprehensive device information."""
        info = self.gpu_info.copy()

        # Add additional runtime info if available
        if GPU_AUTOLOADER_AVAILABLE:
            try:
                from ..utils.torch_gil_safety import safe_torch_import

                torch = safe_torch_import()
                if torch is None:
                    raise ImportError("PyTorch not available")

                if self.gpu_info["type"] == "intel_xpu" and hasattr(torch, "xpu"):
                    info["runtime"] = {
                        "xpu_available": torch.xpu.is_available(),
                        "device_count": torch.xpu.device_count() if torch.xpu.is_available() else 0,
                    }
                elif self.gpu_info["type"] == "nvidia_cuda" and torch.cuda.is_available():
                    info["runtime"] = {
                        "cuda_available": True,
                        "device_count": torch.cuda.device_count(),
                        "current_device": torch.cuda.current_device(),
                    }
                elif self.gpu_info["type"] == "amd_rocm" and hasattr(torch, "hip"):
                    info["runtime"] = {
                        "hip_available": torch.hip.is_available() if hasattr(torch.hip, "is_available") else False,
                        "device_count": torch.hip.device_count() if hasattr(torch.hip, "device_count") else 0,
                    }
            except Exception:
                logger.debug("Failed to get runtime info", exc_info=True)

        return info

    def prepare_model(self, model: object) -> object:
        """Prepare model for GPU execution.

        Args:
            model: PyTorch model object to prepare for execution.

        Returns:
            object: Prepared model ready for GPU or CPU execution.

        """
        # Move to device
        model = to_device(model)

        # Optimize for specific backend
        model = optimize_for_gpu(model)

        return model

    def prepare_tensor(self, tensor: object) -> object:
        """Prepare tensor for GPU execution.

        Args:
            tensor: PyTorch tensor object to prepare for execution.

        Returns:
            object: Prepared tensor ready for GPU or CPU execution.

        """
        return to_device(tensor)

    def get_memory_usage(self) -> dict[str, object]:
        """Get current GPU memory usage."""
        return _gpu_autoloader_instance.get_memory_info()

    def synchronize(self) -> None:
        """Synchronize GPU operations."""
        _gpu_autoloader_instance.synchronize()

    def is_available(self) -> bool:
        """Check if GPU acceleration is available."""
        available = self.gpu_info.get("available")
        if isinstance(available, bool):
            return available
        return False

    def get_backend_name(self) -> str:
        """Get the backend name."""
        info = self.gpu_info.get("info", {})
        if isinstance(info, dict):
            backend = info.get("backend", "Unknown")
            if isinstance(backend, str):
                return backend
        return "Unknown"


# Global instance
gpu_integration = GPUIntegration()


# Export convenience functions
def get_ai_device() -> object:
    """Get device for AI operations.

    Returns:
        object: The compute device for AI operations.

    """
    return gpu_integration.device


def prepare_ai_model(model: object) -> object:
    """Prepare AI model for GPU execution.

    Args:
        model: PyTorch model object to prepare for GPU execution.

    Returns:
        object: Prepared model ready for execution on GPU or CPU.

    """
    return gpu_integration.prepare_model(model)


def prepare_ai_tensor(tensor: object) -> object:
    """Prepare tensor for GPU execution.

    Args:
        tensor: PyTorch tensor object to prepare for GPU execution.

    Returns:
        object: Prepared tensor ready for execution on GPU or CPU.

    """
    return gpu_integration.prepare_tensor(tensor)


def get_ai_gpu_info() -> dict[str, Any]:
    """Get GPU information for AI operations.

    Returns:
        dict[str, Any]: Comprehensive GPU and device information.

    """
    return gpu_integration.get_device_info()


def is_gpu_available() -> bool:
    """Check if GPU is available for AI operations.

    Returns:
        bool: True if GPU acceleration is available, False otherwise.

    """
    return gpu_integration.is_available()
