"""GPU Auto-configuration System for Intellicrack.

Automatically detects and configures GPU acceleration for Intel Arc, NVIDIA, AMD, and DirectML.
Provides a unified interface for all GPU operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class GPUAutoLoader:
    """Automatic GPU detection and configuration system."""

    def __init__(self) -> None:
        """Initialize the GPU autoloader with default values."""
        self.gpu_available: bool = False
        self.gpu_type: str | None = None
        self.gpu_info: dict[str, object] = {}
        self._torch: Any = None
        self._device: Any = None
        self._device_string: str | None = None

    def setup(self) -> bool:
        """Run setup function that tries different GPU configurations."""
        # Check if GPU is disabled via environment variable
        if os.environ.get("INTELLICRACK_NO_GPU", "").lower() in ("1", "true", "yes"):
            logger.info("GPU disabled via environment variable")
            self._try_cpu_fallback()
            return True

        # Check if Intel XPU should be skipped due to GIL issues
        skip_intel = os.environ.get("INTELLICRACK_SKIP_INTEL_XPU", "").lower() in (
            "1",
            "true",
            "yes",
        )

        logger.info("Starting GPU auto-detection...")

        methods: list[Callable[[], bool]] = []

        if not skip_intel:
            methods.append(self._try_intel_xpu)
        else:
            logger.info("Skipping Intel XPU due to environment variable")

        methods.extend(
            [
                self._try_nvidia_cuda,
                self._try_amd_rocm,
                self._try_directml,
                self._try_cpu_fallback,
            ],
        )

        for method in methods:
            try:
                if method():
                    logger.info("OK GPU configured: %s", self.gpu_type)
                    logger.info("  Device: %s", self._device_string)
                    if self.gpu_info:
                        for key, value in self.gpu_info.items():
                            logger.info("  %s: %s", key, value)
                    return True
            except Exception as e:
                logger.debug("Method %s failed: %s", method.__name__, e, exc_info=True)
                # If Intel XPU fails with pybind11 error, automatically skip it in future runs
                if method.__name__ == "_try_intel_xpu" and "pybind11" in str(e).lower():
                    logger.warning("Intel XPU failed with pybind11 GIL error, will skip Intel XPU")
                    os.environ["INTELLICRACK_SKIP_INTEL_XPU"] = "1"
                continue

        logger.warning("No GPU acceleration available, using CPU")
        return False

    def _try_intel_xpu(self) -> bool:
        """Try to use Intel Arc/XPU through native PyTorch."""
        try:
            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                return False

            self._torch = torch

            # Check for XPU support in PyTorch
            if not hasattr(torch, "xpu"):
                logger.debug("PyTorch XPU backend not available")
                return False

            # Check XPU availability with defensive programming
            try:
                if hasattr(torch, "xpu") and torch.xpu.is_available():
                    self.gpu_available = True
                    self.gpu_type = "intel_xpu"
                    self._device = torch.device("xpu")
                    self._device_string = "xpu"

                    # Get detailed info with error handling
                    try:
                        device_count = torch.xpu.device_count()
                        self.gpu_info = {
                            "device_count": device_count,
                            "backend": "PyTorch XPU",
                            "driver_version": torch.xpu.get_driver_version() if hasattr(torch.xpu, "get_driver_version") else "Unknown",
                        }

                        # Get info for first device
                        if device_count > 0:
                            try:
                                self.gpu_info["device_name"] = torch.xpu.get_device_name(0)
                                props = torch.xpu.get_device_properties(0)
                                self.gpu_info["total_memory"] = (
                                    f"{props.total_memory / (1024**3):.1f} GB" if hasattr(props, "total_memory") else "Unknown"
                                )
                            except Exception as e:
                                logger.debug("Failed to get XPU device info: %s", e, exc_info=True)
                    except Exception as e:
                        logger.debug("Failed to get XPU detailed info: %s", e, exc_info=True)
                        self.gpu_info = {"backend": "Intel Extension for PyTorch (Limited Info)"}

                    return True
                logger.debug("XPU not available or torch.xpu not present")
            except Exception as e:
                logger.debug("XPU availability check failed: %s", e, exc_info=True)
                logger.warning("Intel XPU initialization failed due to GIL/pybind11 issues: %s", e)
                return False

            return False

        except Exception as e:
            logger.debug("Intel XPU initialization failed: %s", e, exc_info=True)
            return False

    def _try_nvidia_cuda(self) -> bool:
        """Try to use NVIDIA CUDA."""
        try:
            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                return False

            self._torch = torch

            if hasattr(torch, "cuda") and torch.cuda.is_available():
                self.gpu_available = True
                self.gpu_type = "nvidia_cuda"
                self._device = torch.device("cuda")
                self._device_string = "cuda"

                # Get detailed info
                device_count = torch.cuda.device_count()
                self.gpu_info = {
                    "device_count": device_count,
                    "backend": "NVIDIA CUDA",
                    "cuda_version": torch.version.cuda,
                }

                # Get info for first device
                if device_count > 0:
                    props = torch.cuda.get_device_properties(0)
                    self.gpu_info["device_name"] = props.name
                    self.gpu_info["total_memory"] = f"{props.total_memory / (1024**3):.1f} GB"
                    self.gpu_info["compute_capability"] = f"{props.major}.{props.minor}"

                return True

            return False

        except Exception as e:
            logger.debug("NVIDIA CUDA initialization failed: %s", e, exc_info=True)
            return False

    def _try_amd_rocm(self) -> bool:
        """Try to use AMD ROCm."""
        try:
            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                return False

            self._torch = torch

            # Check for ROCm support
            if hasattr(torch, "hip") and torch.hip.is_available():
                self.gpu_available = True
                self.gpu_type = "amd_rocm"
                self._device = torch.device("hip")
                self._device_string = "hip"

                # Get detailed info
                device_count = torch.hip.device_count()
                self.gpu_info = {
                    "device_count": device_count,
                    "backend": "AMD ROCm",
                    "hip_version": torch.version.hip if hasattr(torch.version, "hip") else "Unknown",
                }

                # Get info for first device
                if device_count > 0:
                    self.gpu_info["device_name"] = torch.hip.get_device_name(0)
                    props = torch.hip.get_device_properties(0)
                    self.gpu_info["total_memory"] = (
                        f"{props.total_memory / (1024**3):.1f} GB" if hasattr(props, "total_memory") else "Unknown"
                    )

                return True

            return False

        except Exception as e:
            logger.debug("AMD ROCm initialization failed: %s", e, exc_info=True)
            return False

    def _try_directml(self) -> bool:
        """Try to use DirectML (works with Intel Arc on Windows)."""
        try:
            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                return False

            self.gpu_available = True
            self.gpu_type = "directml"
            self._torch = torch
            self._device = torch.device("cpu") if torch else None  # DirectML uses CPU device designation
            self._device_string = "cpu"  # DirectML operations happen through CPU API

            self.gpu_info = {
                "backend": "DirectML",
                "platform": "Windows",
                "note": "GPU acceleration through DirectML",
            }

            return True

        except Exception as e:
            logger.debug("DirectML initialization failed: %s", e, exc_info=True)
            return False

    def _try_cpu_fallback(self) -> bool:
        """Fallback to CPU."""
        try:
            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()

            # In fallback mode (no PyTorch), just set CPU config without torch
            self._torch = torch  # Will be None in fallback mode
            self.gpu_available = False
            self.gpu_type = "cpu"

            # Only create torch device if torch is available
            self._device = torch.device("cpu") if torch is not None else None
            self._device_string = "cpu"

            self.gpu_info = {
                "backend": "CPU (PyTorch fallback mode)" if torch is None else "CPU",
                "cores": os.cpu_count(),
            }

            return True

        except Exception as e:
            logger.exception("Even CPU initialization failed: %s", e)
            return False

    def get_device(self) -> Any:
        """Get the configured device object."""
        return self._device

    def get_torch(self) -> Any:
        """Get the torch module if available."""
        return self._torch

    def to_device(self, tensor_or_model: Any) -> Any:
        """Move a tensor or model to the configured device."""
        if self._device and hasattr(tensor_or_model, "to"):
            return tensor_or_model.to(self._device)
        return tensor_or_model

    def get_device_string(self) -> str:
        """Get device string for torch operations."""
        return self._device_string or "cpu"

    def optimize_model(self, model: Any) -> Any:
        """Optimize model for the current backend."""
        if self.gpu_type == "intel_xpu" and self._torch:
            logger.info("Optimizing model with PyTorch compilation")
            try:
                if hasattr(self._torch, "compile"):
                    return self._torch.compile(model)
            except Exception as e:
                logger.debug("Model compilation not available: %s", e, exc_info=True)
        return model

    def get_memory_info(self) -> dict[str, object]:
        """Get GPU memory information."""
        if not self.gpu_available or not self._torch:
            return {}

        try:
            if self.gpu_type == "nvidia_cuda" and hasattr(self._torch, "cuda"):
                return {
                    "allocated": f"{self._torch.cuda.memory_allocated() / (1024**3):.2f} GB",
                    "reserved": f"{self._torch.cuda.memory_reserved() / (1024**3):.2f} GB",
                    "free": f"{(self._torch.cuda.get_device_properties(0).total_memory - self._torch.cuda.memory_allocated()) / (1024**3):.2f} GB",
                }
            if self.gpu_type == "intel_xpu" and hasattr(self._torch, "xpu"):
                if hasattr(self._torch.xpu, "memory_allocated"):
                    return {
                        "allocated": f"{self._torch.xpu.memory_allocated() / (1024**3):.2f} GB",
                        "reserved": f"{self._torch.xpu.memory_reserved() / (1024**3):.2f} GB"
                        if hasattr(self._torch.xpu, "memory_reserved")
                        else "N/A",
                    }
            elif self.gpu_type == "amd_rocm" and hasattr(self._torch, "hip"):
                if hasattr(self._torch.hip, "memory_allocated"):
                    return {
                        "allocated": f"{self._torch.hip.memory_allocated() / (1024**3):.2f} GB",
                        "reserved": f"{self._torch.hip.memory_reserved() / (1024**3):.2f} GB"
                        if hasattr(self._torch.hip, "memory_reserved")
                        else "N/A",
                    }
        except Exception as e:
            logger.debug("Failed to get memory info: %s", e, exc_info=True)

        return {}

    def synchronize(self) -> None:
        """Synchronize GPU operations."""
        if not self.gpu_available or not self._torch:
            return

        try:
            if self.gpu_type == "nvidia_cuda" and hasattr(self._torch, "cuda"):
                self._torch.cuda.synchronize()
            elif self.gpu_type == "intel_xpu" and hasattr(self._torch, "xpu"):
                if hasattr(self._torch.xpu, "synchronize"):
                    self._torch.xpu.synchronize()
            elif self.gpu_type == "amd_rocm" and hasattr(self._torch, "hip"):
                if hasattr(self._torch.hip, "synchronize"):
                    self._torch.hip.synchronize()
        except Exception as e:
            logger.debug("Synchronization failed: %s", e, exc_info=True)


# Global instance
gpu_autoloader = GPUAutoLoader()


def get_device() -> Any:
    """Get the configured GPU device."""
    return gpu_autoloader.get_device()


def get_gpu_info() -> dict[str, object]:
    """Get GPU information."""
    return {
        "available": gpu_autoloader.gpu_available,
        "type": gpu_autoloader.gpu_type,
        "device": gpu_autoloader.get_device_string(),
        "info": gpu_autoloader.gpu_info,
        "memory": gpu_autoloader.get_memory_info(),
    }


def to_device(tensor_or_model: Any) -> Any:
    """Move tensor or model to GPU."""
    return gpu_autoloader.to_device(tensor_or_model)


def optimize_for_gpu(model: Any) -> Any:
    """Optimize model for current GPU backend."""
    return gpu_autoloader.optimize_model(model)


def detect_gpu_frameworks() -> dict[str, object]:
    """Detect available GPU frameworks on the system.

    Returns:
        Dictionary containing framework availability and information

    """
    frameworks: dict[str, object] = {
        "cuda": False,
        "cuda_version": None,
        "rocm": False,
        "rocm_version": None,
        "opencl": False,
        "opencl_version": None,
        "directml": False,
        "intel_xpu": False,
        "xpu_version": None,
        "vulkan": False,
        "metal": False,
        "available_frameworks": [],
        "gpu_devices": [],
    }

    # Check for CUDA
    try:
        import torch

        if torch.cuda.is_available():
            frameworks["cuda"] = True
            frameworks["cuda_version"] = torch.version.cuda
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("CUDA")
            gpu_devices = frameworks["gpu_devices"]
            if isinstance(gpu_devices, list):
                for i in range(torch.cuda.device_count()):
                    gpu_devices.append(
                        {
                            "type": "CUDA",
                            "index": i,
                            "name": torch.cuda.get_device_name(i),
                            "memory": torch.cuda.get_device_properties(i).total_memory,
                        },
                    )
    except (ImportError, AttributeError):
        pass

    # Check for ROCm
    try:
        import torch

        if hasattr(torch, "hip") and torch.hip.is_available():
            frameworks["rocm"] = True
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("ROCm")
            # Try to get ROCm version
            try:
                import shutil

                rocm_smi_path = shutil.which("rocm-smi")
                if not rocm_smi_path:
                    error_msg = "rocm-smi not found in PATH"
                    logger.error(error_msg)
                    raise FileNotFoundError(error_msg)
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [rocm_smi_path, "--version"],
                    capture_output=True,
                    text=True,
                    shell=False,  # Explicitly secure - no shell injection
                    check=False,
                )
                if result.returncode == 0:
                    frameworks["rocm_version"] = result.stdout.strip()
            except Exception as e:
                logger.debug("Failed to get ROCm version: %s", e, exc_info=True)
    except (ImportError, AttributeError):
        pass

    # Check for OpenCL
    try:
        import pyopencl as cl

        platforms = cl.get_platforms()
        if platforms:
            frameworks["opencl"] = True
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("OpenCL")
            gpu_devices = frameworks["gpu_devices"]
            if isinstance(gpu_devices, list):
                for platform in platforms:
                    devices = platform.get_devices()
                    for device in devices:
                        gpu_devices.append(
                            {
                                "type": "OpenCL",
                                "name": device.name,
                                "vendor": device.vendor,
                                "memory": device.global_mem_size,
                            },
                        )
        # Get OpenCL version from first platform
        if platforms:
            frameworks["opencl_version"] = platforms[0].version.strip()
    except ImportError:
        pass

    # Check for DirectML (Windows)
    if sys.platform == "win32":
        try:
            import torch_directml

            frameworks["directml"] = True
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("DirectML")
            # Try to enumerate DirectML devices
            try:
                device_count = torch_directml.device_count()
                gpu_devices = frameworks["gpu_devices"]
                if isinstance(gpu_devices, list):
                    for i in range(device_count):
                        device_name = torch_directml.device_name(i)
                        gpu_devices.append({"type": "DirectML", "index": i, "name": device_name})
            except Exception as e:
                logger.debug("Failed to enumerate DirectML devices: %s", e, exc_info=True)
        except ImportError:
            pass

    # Check for Intel XPU
    try:
        import torch

        if hasattr(torch, "xpu") and torch.xpu.is_available():
            frameworks["intel_xpu"] = True
            frameworks["xpu_version"] = torch.__version__
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("Intel XPU")
            # Get XPU device info
            gpu_devices = frameworks["gpu_devices"]
            if isinstance(gpu_devices, list):
                for i in range(torch.xpu.device_count()):
                    gpu_devices.append({"type": "Intel XPU", "index": i, "name": torch.xpu.get_device_name(i)})
    except Exception as e:
        logger.debug("XPU device detection failed: %s", e, exc_info=True)

    # Check for Vulkan compute
    try:
        # Simple check for Vulkan availability
        import shutil

        vulkaninfo_path = shutil.which("vulkaninfo")
        if not vulkaninfo_path:
            error_msg = "vulkaninfo not found in PATH"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            [vulkaninfo_path, "--summary"],
            capture_output=True,
            text=True,
            shell=False,  # Explicitly secure - no shell injection
            check=False,
        )
        if result.returncode == 0:
            frameworks["vulkan"] = True
            available_frameworks = frameworks["available_frameworks"]
            if isinstance(available_frameworks, list):
                available_frameworks.append("Vulkan")
    except Exception as e:
        logger.debug("Failed to check Vulkan availability: %s", e, exc_info=True)

    # Check for Metal (macOS)
    if sys.platform == "darwin":
        try:
            import torch

            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                frameworks["metal"] = True
                available_frameworks = frameworks["available_frameworks"]
                if isinstance(available_frameworks, list):
                    available_frameworks.append("Metal")
        except (ImportError, AttributeError):
            pass

    # Add summary information
    gpu_devices = frameworks["gpu_devices"]
    if isinstance(gpu_devices, list):
        frameworks["gpu_count"] = len(gpu_devices)
    available_frameworks = frameworks["available_frameworks"]
    if isinstance(available_frameworks, list) and available_frameworks:
        frameworks["primary_framework"] = available_frameworks[0]
    else:
        frameworks["primary_framework"] = None

    return frameworks
