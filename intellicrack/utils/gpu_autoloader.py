"""GPU Auto-configuration System for Intellicrack.

Automatically detects and configures GPU acceleration for Intel Arc, NVIDIA, AMD, and DirectML.
Provides a unified interface for all GPU operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)


class GPUAutoLoader:
    """Automatic GPU detection and configuration system."""

    def __init__(self) -> None:
        """Initialize the GPU autoloader with default values."""
        self.gpu_available: bool = False
        self.gpu_type: str | None = None
        self.gpu_info: dict[str, object] = {}
        self._torch: object | None = None
        self._device: object | None = None
        self._ipex: object | None = None
        self._device_string: str | None = None

    def setup(self) -> bool:
        """Run setup function that tries different GPU configurations."""
        # Check if GPU is disabled via environment variable
        if os.environ.get("INTELLICRACK_NO_GPU", "").lower() in ("1", "true", "yes"):
            logger.info("GPU disabled via environment variable")
            self._try_cpu_fallback()
            return True

        # Check if Intel XPU should be skipped due to GIL issues
        skip_intel = os.environ.get("INTELLICRACK_SKIP_INTEL_XPU", "").lower() in ("1", "true", "yes")

        logger.info("Starting GPU auto-detection...")

        methods = []

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
                    logger.info(f"OK GPU configured: {self.gpu_type}")
                    logger.info(f"  Device: {self._device_string}")
                    if self.gpu_info:
                        for key, value in self.gpu_info.items():
                            logger.info(f"  {key}: {value}")
                    return True
            except Exception as e:
                logger.debug(f"Method {method.__name__} failed: {e}")
                # If Intel XPU fails with pybind11 error, automatically skip it in future runs
                if method.__name__ == "_try_intel_xpu" and "pybind11" in str(e).lower():
                    logger.warning("Intel XPU failed with pybind11 GIL error, will skip Intel XPU")
                    os.environ["INTELLICRACK_SKIP_INTEL_XPU"] = "1"
                continue

        logger.warning("No GPU acceleration available, using CPU")
        return False

    def _try_intel_xpu(self) -> bool:
        """Try to use Intel Arc/XPU through Intel Extension for PyTorch."""
        try:
            # First check if we have a conda environment with Intel Extension
            conda_envs = self._find_conda_envs_with_ipex()
            if conda_envs:
                logger.info(f"Found {len(conda_envs)} conda environment(s) with Intel Extension for PyTorch")
                # Try to use the first one
                conda_env = conda_envs[0]
                python_path = os.path.join(conda_env["path"], "python.exe" if sys.platform == "win32" else "python")

                # Test if we can import from that environment
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    [
                        python_path,
                        "-c",
                        "import torch; import intel_extension_for_pytorch as ipex; print(torch.xpu.is_available())",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,  # 5 second timeout to prevent hanging
                )

                if result.returncode == 0 and "True" in result.stdout:
                    # Inject the conda environment's packages
                    self._inject_conda_packages(conda_env["path"])

            # Use thread-safe PyTorch import
            from .torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                return False

            self._torch = torch

            # Check for Intel Extension with GIL safety handling
            try:
                from intellicrack.handlers.ipex_handler import HAS_IPEX, ipex

                if HAS_IPEX:
                    self._ipex = ipex
                    logger.debug("Intel Extension for PyTorch imported successfully via handler")
                else:
                    logger.debug("Intel Extension for PyTorch not available (see ipex_handler logs)")
                    self._ipex = None
                    return False

            except Exception as e:
                logger.warning(f"Failed to import Intel Extension handler: {e}")
                self._ipex = None

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
                            "backend": "Intel Extension for PyTorch",
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
                                logger.debug(f"Failed to get XPU device info: {e}")
                    except Exception as e:
                        logger.debug(f"Failed to get XPU detailed info: {e}")
                        self.gpu_info = {"backend": "Intel Extension for PyTorch (Limited Info)"}

                    return True
                logger.debug("XPU not available or torch.xpu not present")
            except Exception as e:
                logger.debug(f"XPU availability check failed: {e}")
                # If XPU check fails due to GIL issues, fall back to CPU with warning
                logger.warning(f"Intel XPU initialization failed due to GIL/pybind11 issues: {e}")
                return False

            return False

        except Exception as e:
            logger.debug(f"Intel XPU initialization failed: {e}")
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
            logger.debug(f"NVIDIA CUDA initialization failed: {e}")
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
            logger.debug(f"AMD ROCm initialization failed: {e}")
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
            logger.debug(f"DirectML initialization failed: {e}")
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
            if torch is not None:
                self._device = torch.device("cpu")
            else:
                self._device = None  # No torch available

            self._device_string = "cpu"

            self.gpu_info = {
                "backend": "CPU (PyTorch fallback mode)" if torch is None else "CPU",
                "cores": os.cpu_count(),
            }

            return True

        except Exception as e:
            logger.error(f"Even CPU initialization failed: {e}")
            return False

    def _find_conda_envs_with_ipex(self) -> list[dict[str, str]]:
        """Find conda environments that have Intel Extension for PyTorch installed."""
        conda_envs = []

        # Common conda locations
        possible_conda_bases = [
            os.path.expanduser("~/miniconda3"),
            os.path.expanduser("~/anaconda3"),
            "C:\\ProgramData\\miniconda3",
            "C:\\ProgramData\\anaconda3",
            "C:\\tools\\miniconda3",
            "C:\\tools\\anaconda3",
            os.environ.get("CONDA_PREFIX", ""),
        ]

        for base in possible_conda_bases:
            if not base or not os.path.exists(base):
                continue

            envs_dir = os.path.join(base, "envs")
            if os.path.exists(envs_dir):
                for env_name in os.listdir(envs_dir):
                    env_path = os.path.join(envs_dir, env_name)
                    # Check for Intel Extension for PyTorch
                    ipex_indicators = [
                        os.path.join(env_path, "Lib", "site-packages", "intel_extension_for_pytorch"),
                        os.path.join(
                            env_path,
                            "lib",
                            "python3.9",
                            "site-packages",
                            "intel_extension_for_pytorch",
                        ),
                        os.path.join(
                            env_path,
                            "lib",
                            "python3.10",
                            "site-packages",
                            "intel_extension_for_pytorch",
                        ),
                        os.path.join(
                            env_path,
                            "lib",
                            "python3.11",
                            "site-packages",
                            "intel_extension_for_pytorch",
                        ),
                    ]

                    for indicator in ipex_indicators:
                        if os.path.exists(indicator):
                            conda_envs.append(
                                {
                                    "name": env_name,
                                    "path": env_path,
                                    "base": base,
                                },
                            )
                            break

        return conda_envs

    def _inject_conda_packages(self, conda_env_path: str) -> None:
        """Inject conda environment packages into current Python path."""
        # Add conda environment's site-packages to Python path
        if sys.platform == "win32":
            site_packages = os.path.join(conda_env_path, "Lib", "site-packages")
        else:
            # Try multiple Python versions
            for py_ver in ["python3.11", "python3.10", "python3.9", "python3.8"]:
                site_packages = os.path.join(conda_env_path, "lib", py_ver, "site-packages")
                if os.path.exists(site_packages):
                    break

        if os.path.exists(site_packages) and site_packages not in sys.path:
            sys.path.insert(0, site_packages)
            logger.info(f"Injected conda packages from: {site_packages}")

    def get_device(self) -> object | None:
        """Get the configured device object."""
        return self._device

    def get_torch(self) -> object | None:
        """Get the torch module if available."""
        return self._torch

    def get_ipex(self) -> object | None:
        """Get the Intel Extension module if available."""
        return self._ipex

    def to_device(self, tensor_or_model: object) -> object:
        """Move a tensor or model to the configured device."""
        if self._device and hasattr(tensor_or_model, "to"):
            return tensor_or_model.to(self._device)
        return tensor_or_model

    def get_device_string(self) -> str:
        """Get device string for torch operations."""
        return self._device_string or "cpu"

    def optimize_model(self, model: object) -> object:
        """Optimize model for the current backend."""
        if self.gpu_type == "intel_xpu" and self._ipex:
            logger.info("Optimizing model with Intel Extension for PyTorch")
            return self._ipex.optimize(model)
        return model

    def get_memory_info(self) -> dict[str, object]:
        """Get GPU memory information."""
        if not self.gpu_available or not self._torch:
            return {}

        try:
            if self.gpu_type == "nvidia_cuda":
                return {
                    "allocated": f"{self._torch.cuda.memory_allocated() / (1024**3):.2f} GB",
                    "reserved": f"{self._torch.cuda.memory_reserved() / (1024**3):.2f} GB",
                    "free": f"{(self._torch.cuda.get_device_properties(0).total_memory - self._torch.cuda.memory_allocated()) / (1024**3):.2f} GB",
                }
            if self.gpu_type == "intel_xpu":
                if hasattr(self._torch.xpu, "memory_allocated"):
                    return {
                        "allocated": f"{self._torch.xpu.memory_allocated() / (1024**3):.2f} GB",
                        "reserved": f"{self._torch.xpu.memory_reserved() / (1024**3):.2f} GB"
                        if hasattr(self._torch.xpu, "memory_reserved")
                        else "N/A",
                    }
            elif self.gpu_type == "amd_rocm":
                if hasattr(self._torch.hip, "memory_allocated"):
                    return {
                        "allocated": f"{self._torch.hip.memory_allocated() / (1024**3):.2f} GB",
                        "reserved": f"{self._torch.hip.memory_reserved() / (1024**3):.2f} GB"
                        if hasattr(self._torch.hip, "memory_reserved")
                        else "N/A",
                    }
        except Exception as e:
            logger.debug(f"Failed to get memory info: {e}")

        return {}

    def synchronize(self) -> None:
        """Synchronize GPU operations."""
        if not self.gpu_available or not self._torch:
            return

        try:
            if self.gpu_type == "nvidia_cuda":
                self._torch.cuda.synchronize()
            elif self.gpu_type == "intel_xpu":
                if hasattr(self._torch.xpu, "synchronize"):
                    self._torch.xpu.synchronize()
            elif self.gpu_type == "amd_rocm":
                if hasattr(self._torch.hip, "synchronize"):
                    self._torch.hip.synchronize()
        except Exception as e:
            logger.debug(f"Synchronization failed: {e}")


# Global instance
gpu_autoloader = GPUAutoLoader()


def get_device() -> object | None:
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


def to_device(tensor_or_model: object) -> object:
    """Move tensor or model to GPU."""
    return gpu_autoloader.to_device(tensor_or_model)


def optimize_for_gpu(model: object) -> object:
    """Optimize model for current GPU backend."""
    return gpu_autoloader.optimize_model(model)


def detect_gpu_frameworks() -> dict[str, object]:
    """Detect available GPU frameworks on the system.

    Returns:
        Dictionary containing framework availability and information

    """
    frameworks = {
        "cuda": False,
        "cuda_version": None,
        "rocm": False,
        "rocm_version": None,
        "opencl": False,
        "opencl_version": None,
        "directml": False,
        "intel_xpu": False,
        "ipex_version": None,
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
            frameworks["available_frameworks"].append("CUDA")
            for i in range(torch.cuda.device_count()):
                frameworks["gpu_devices"].append(
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
            frameworks["available_frameworks"].append("ROCm")
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
                logger.debug(f"Failed to get ROCm version: {e}")
    except (ImportError, AttributeError):
        pass

    # Check for OpenCL
    try:
        import pyopencl as cl

        platforms = cl.get_platforms()
        if platforms:
            frameworks["opencl"] = True
            frameworks["available_frameworks"].append("OpenCL")
            for platform in platforms:
                devices = platform.get_devices()
                for device in devices:
                    frameworks["gpu_devices"].append(
                        {"type": "OpenCL", "name": device.name, "vendor": device.vendor, "memory": device.global_mem_size},
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
            frameworks["available_frameworks"].append("DirectML")
            # Try to enumerate DirectML devices
            try:
                device_count = torch_directml.device_count()
                for i in range(device_count):
                    device_name = torch_directml.device_name(i)
                    frameworks["gpu_devices"].append({"type": "DirectML", "index": i, "name": device_name})
            except Exception as e:
                logger.debug(f"Failed to enumerate DirectML devices: {e}")
        except ImportError:
            pass

    # Check for Intel XPU
    try:
        import torch

        from intellicrack.handlers.ipex_handler import HAS_IPEX, ipex

        if HAS_IPEX and hasattr(torch, "xpu") and torch.xpu.is_available():
            frameworks["intel_xpu"] = True
            frameworks["ipex_version"] = ipex.__version__
            frameworks["available_frameworks"].append("Intel XPU")
            # Get XPU device info
            for i in range(torch.xpu.device_count()):
                frameworks["gpu_devices"].append({"type": "Intel XPU", "index": i, "name": torch.xpu.get_device_name(i)})
    except (ImportError, Exception) as e:
        logger.debug(f"XPU device detection failed: {e}")

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
            frameworks["available_frameworks"].append("Vulkan")
    except Exception as e:
        logger.debug(f"Failed to check Vulkan availability: {e}")

    # Check for Metal (macOS)
    if sys.platform == "darwin":
        try:
            import torch

            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                frameworks["metal"] = True
                frameworks["available_frameworks"].append("Metal")
        except (ImportError, AttributeError):
            pass

    # Add summary information
    frameworks["gpu_count"] = len(frameworks["gpu_devices"])
    frameworks["primary_framework"] = frameworks["available_frameworks"][0] if frameworks["available_frameworks"] else None

    return frameworks
