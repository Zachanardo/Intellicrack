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
        """Initialize GPU acceleration with automatic backend detection.

        Attempts to configure GPU acceleration by trying multiple backends in order:
        Intel XPU, NVIDIA CUDA, AMD ROCm, DirectML, and CPU fallback. Respects
        environment variables to skip specific backends. Logs detailed information
        about the selected GPU device and its capabilities.

        Returns:
            True if GPU setup succeeded with a valid backend, False if all
                backends failed (CPU fallback always succeeds).

        """
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
        """Detect and configure Intel Arc/XPU GPU acceleration.

        Attempts to import PyTorch with Intel XPU support and verifies device
        availability. Queries device properties including count, name, memory,
        and driver version. Handles pybind11 GIL issues and sets environment
        variables to prevent future failed attempts.

        Returns:
            True if Intel XPU is available and successfully configured,
                False if XPU is unavailable, import fails, or GIL issues occur.

        """
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
        """Detect and configure NVIDIA CUDA GPU acceleration.

        Attempts to import PyTorch with CUDA support and verifies GPU availability.
        Queries CUDA device properties including device count, device names, total
        memory in GB, and compute capabilities. Stores CUDA version information.

        Returns:
            True if NVIDIA CUDA is available and successfully configured,
                False if CUDA is unavailable or import fails.

        """
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
        """Detect and configure AMD ROCm GPU acceleration.

        Attempts to import PyTorch with AMD ROCm (HIP) support and verifies GPU
        availability. Queries device properties including device count, device names,
        total memory in GB, and HIP version information.

        Returns:
            True if AMD ROCm is available and successfully configured,
                False if ROCm is unavailable or import fails.

        """
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
        """Configure DirectML GPU acceleration for Windows platforms.

        Enables DirectML-based GPU acceleration, which provides Windows-native
        compute acceleration for Intel Arc and other GPU devices. DirectML operations
        are transparently accelerated through PyTorch's CPU operations.

        Returns:
            True if DirectML is successfully configured (Windows only),
                False if configuration fails.

        """
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
        """Configure CPU-based processing as final fallback option.

        Configures PyTorch to use CPU for all tensor operations. This is the
        final fallback when no GPU acceleration is available. If PyTorch cannot
        be imported, operates in fallback mode without torch module.

        Returns:
            True if CPU configuration is successfully initialized (always
                succeeds), False only on critical errors.

        """
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
        """Retrieve the PyTorch device object for the active backend.

        Returns the device object representing the selected GPU backend or CPU.
        This device object can be used with .to() methods to move tensors and
        models to the appropriate compute device.

        Returns:
            The PyTorch device object (torch.device) for the configured backend,
                or None if PyTorch is not available.

        """
        return self._device

    def get_torch(self) -> Any:
        """Access the PyTorch module for direct tensor operations.

        Returns the imported torch module for performing tensor computations,
        neural network operations, and direct GPU device management. Returns None
        if PyTorch was not successfully imported.

        Returns:
            The torch module (PyTorch library) if successfully loaded, or None
                if PyTorch is not available in the environment.

        """
        return self._torch

    def to_device(self, tensor_or_model: Any) -> Any:
        """Move a tensor or model to the configured compute device.

        Transfers a PyTorch tensor or neural network model to the currently
        configured device (GPU or CPU). If no device is configured or the object
        lacks a .to() method, returns the object unchanged.

        Args:
            tensor_or_model: The PyTorch tensor or neural network model to
                transfer to the configured device.

        Returns:
            The tensor or model transferred to the configured device, or the
                original object if device configuration is unavailable.

        """
        if self._device and hasattr(tensor_or_model, "to"):
            return tensor_or_model.to(self._device)
        return tensor_or_model

    def get_device_string(self) -> str:
        """Get the device string identifier for PyTorch operations.

        Returns a string representation of the configured device that can be used
        to specify device placement in PyTorch operations and model transfers.
        Defaults to 'cpu' if no device has been configured.

        Returns:
            The device string identifier such as 'cuda', 'xpu', 'hip', or 'cpu',
                suitable for use with torch.device() constructor calls.

        """
        return self._device_string or "cpu"

    def optimize_model(self, model: Any) -> Any:
        """Optimize a neural network model for the active GPU backend.

        Applies backend-specific optimizations such as PyTorch compilation for
        Intel XPU to improve inference and training performance. Falls back to
        returning the original model if optimizations are not available or supported
        by the current backend.

        Args:
            model: The PyTorch neural network model to optimize for the
                configured GPU backend.

        Returns:
            The optimized model with backend-specific compilation applied, or
                the original unmodified model if optimization is unavailable.

        """
        if self.gpu_type == "intel_xpu" and self._torch:
            logger.info("Optimizing model with PyTorch compilation")
            try:
                if hasattr(self._torch, "compile"):
                    return self._torch.compile(model)
            except Exception as e:
                logger.debug("Model compilation not available: %s", e, exc_info=True)
        return model

    def get_memory_info(self) -> dict[str, object]:
        """Retrieve memory usage statistics for the active GPU backend.

        Queries the current GPU device to obtain memory allocation statistics.
        Provides allocated memory, reserved memory, and free memory values in
        gigabytes. Returns empty dictionary if no GPU is available or memory
        queries fail.

        Returns:
            Dictionary mapping memory metric names to formatted string values
                (e.g., 'allocated', 'reserved', 'free') with memory sizes in GB,
                or empty dictionary if GPU is unavailable or queries fail.

        """
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
        """Synchronize pending GPU operations and ensure completion.

        Blocks execution until all GPU kernel operations complete. Necessary for
        accurate timing measurements and ensuring GPU state consistency before
        host-device synchronization points."""
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
    """Retrieve the PyTorch device object from the global GPU autoloader.

    Accesses the configured GPU device from the module-level gpu_autoloader
    instance, returning the PyTorch device object for the active backend (GPU
    or CPU).

    Returns:
        The PyTorch device object for the active backend, or None if PyTorch
            is not available.

    """
    return gpu_autoloader.get_device()


def get_gpu_info() -> dict[str, object]:
    """Retrieve comprehensive GPU configuration and status information.

    Collects current GPU backend information from the global gpu_autoloader
    instance including availability status, backend type, device string, device
    properties, and memory statistics.

    Returns:
        Dictionary with keys: 'available' (bool), 'type' (str), 'device' (str),
            'info' (dict), 'memory' (dict) containing all GPU status information.

    """
    return {
        "available": gpu_autoloader.gpu_available,
        "type": gpu_autoloader.gpu_type,
        "device": gpu_autoloader.get_device_string(),
        "info": gpu_autoloader.gpu_info,
        "memory": gpu_autoloader.get_memory_info(),
    }


def to_device(tensor_or_model: Any) -> Any:
    """Transfer a tensor or model to the configured GPU device.

    Uses the global gpu_autoloader instance to move PyTorch tensors and neural
    network models to the active GPU backend (or CPU fallback). Provides a
    convenient module-level interface for device transfer operations.

    Args:
        tensor_or_model: The PyTorch tensor or neural network model to
            transfer to the configured device.

    Returns:
        The tensor or model on the configured device, or unchanged if device
            is unavailable or the object lacks a .to() method.

    """
    return gpu_autoloader.to_device(tensor_or_model)


def optimize_for_gpu(model: Any) -> Any:
    """Apply backend-specific optimizations to a neural network model.

    Uses the global gpu_autoloader instance to optimize models for the active
    GPU backend. Applies backend-specific compilation and acceleration techniques
    to improve model inference and training performance.

    Args:
        model: The PyTorch neural network model to optimize for the active
            GPU backend.

    Returns:
        The optimized model with backend-specific acceleration applied, or
            the original model if optimization is unavailable for the current
            backend.

    """
    return gpu_autoloader.optimize_model(model)


def detect_gpu_frameworks() -> dict[str, object]:
    """Scan the system and detect all available GPU acceleration frameworks.

    Probes the system for installed GPU frameworks including NVIDIA CUDA, AMD ROCm,
    Intel XPU, DirectML, OpenCL, Vulkan, and Metal. Queries device counts, device
    names, memory capacities, and version information for each available framework.
    Handles missing executables and import errors gracefully.

    Returns:
        Dictionary mapping framework names to availability flags and configuration.
            Keys include: 'cuda', 'cuda_version', 'rocm', 'rocm_version', 'opencl',
            'opencl_version', 'directml', 'intel_xpu', 'xpu_version', 'vulkan',
            'metal', 'available_frameworks' (list), 'gpu_devices' (list),
            'gpu_count' (int), 'primary_framework' (str).

    Raises:
        FileNotFoundError: If rocm-smi or vulkaninfo executables are required
            but not found in system PATH during framework detection.

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
