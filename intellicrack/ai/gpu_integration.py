"""GPU Integration Module for AI Components

This module provides GPU integration for AI components using the unified GPU autoloader system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Import unified GPU system
try:
    from ..utils.gpu_autoloader import (
        get_device,
        get_gpu_info,
        gpu_autoloader,
        optimize_for_gpu,
        to_device,
    )

    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    logger.warning("GPU autoloader not available, using fallback implementations")
    GPU_AUTOLOADER_AVAILABLE = False

    # Fallback implementations
    def get_device():
        """Get the compute device (CPU when GPU not available).

        Returns:
            torch.device: CPU device instance.

        """
        from ..utils.torch_gil_safety import safe_torch_import
        
        torch = safe_torch_import()
        if torch is None:
            # Return string representation if torch not available
            return "cpu"
        return torch.device("cpu")

    def get_gpu_info():
        """Get GPU information (fallback to CPU info).

        Returns:
            dict: Device info indicating CPU-only mode.

        """
        return {
            "available": False,
            "type": "cpu",
            "device": "cpu",
            "info": {},
            "memory": {},
        }

    def to_device(tensor_or_model):
        """Move tensor or model to device (no-op for CPU).

        Args:
            tensor_or_model: PyTorch tensor or model.

        Returns:
            Same tensor or model unchanged.

        """
        return tensor_or_model

    def optimize_for_gpu(model):
        """Optimize model for GPU (no-op for CPU).

        Args:
            model: PyTorch model.

        Returns:
            Same model unchanged.

        """
        return model


class GPUIntegration:
    """GPU Integration for AI models using unified system"""

    def __init__(self):
        """Initialize GPU integration"""
        self.gpu_info = get_gpu_info()
        self.device = get_device()
        logger.info(f"GPU Integration initialized: {self.gpu_info['type']}")

    def get_device_info(self) -> dict[str, Any]:
        """Get comprehensive device information"""
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
                        "hip_available": torch.hip.is_available()
                        if hasattr(torch.hip, "is_available")
                        else False,
                        "device_count": torch.hip.device_count()
                        if hasattr(torch.hip, "device_count")
                        else 0,
                    }
            except Exception as e:
                logger.debug(f"Failed to get runtime info: {e}")

        return info

    def prepare_model(self, model: Any) -> Any:
        """Prepare model for GPU execution"""
        # Move to device
        model = to_device(model)

        # Optimize for specific backend
        model = optimize_for_gpu(model)

        return model

    def prepare_tensor(self, tensor: Any) -> Any:
        """Prepare tensor for GPU execution"""
        return to_device(tensor)

    def get_memory_usage(self) -> dict[str, Any]:
        """Get current GPU memory usage"""
        if GPU_AUTOLOADER_AVAILABLE:
            return gpu_autoloader.get_memory_info()
        return {}

    def synchronize(self):
        """Synchronize GPU operations"""
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_autoloader.synchronize()

    def is_available(self) -> bool:
        """Check if GPU acceleration is available"""
        return self.gpu_info["available"]

    def get_backend_name(self) -> str:
        """Get the backend name"""
        return self.gpu_info.get("info", {}).get("backend", "Unknown")


# Global instance
gpu_integration = GPUIntegration()


# Export convenience functions
def get_ai_device():
    """Get device for AI operations"""
    return gpu_integration.device


def prepare_ai_model(model: Any) -> Any:
    """Prepare AI model for GPU execution"""
    return gpu_integration.prepare_model(model)


def prepare_ai_tensor(tensor: Any) -> Any:
    """Prepare tensor for GPU execution"""
    return gpu_integration.prepare_tensor(tensor)


def get_ai_gpu_info() -> dict[str, Any]:
    """Get GPU information for AI operations"""
    return gpu_integration.get_device_info()


def is_gpu_available() -> bool:
    """Check if GPU is available for AI operations"""
    return gpu_integration.is_available()
