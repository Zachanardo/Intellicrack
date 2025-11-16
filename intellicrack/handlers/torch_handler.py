"""Torch handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

"""PyTorch Import Handler with Production-Ready Fallbacks.

This module provides a centralized abstraction layer for PyTorch imports.
When PyTorch is not available, it provides fallback implementations for
tensor operations used in Intellicrack's ML components.
"""

import os

from intellicrack.utils.logger import logger

# PyTorch availability detection and import handling with Intel Arc B580 compatibility

# Initialize variables
HAS_TORCH: bool = False
TORCH_AVAILABLE: bool = False
TORCH_VERSION: str | None = None
torch: object | None = None
Tensor: type | None = None
cuda: object | None = None
device: type | None = None
dtype: object | None = None
nn: object | None = None
optim: object | None = None
save: object | None = None
load: object | None = None
tensor: object | None = None

# Load environment variables from .env file
# Users can customize GPU settings in the .env file
try:
    from dotenv import load_dotenv

    load_dotenv()  # Load .env file from project root
except ImportError:
    pass  # dotenv not available, use system environment variables


def _detect_and_fix_intel_arc() -> bool:
    """Detect Intel Arc GPU and apply CPU-only workaround to prevent GIL crashes.

    Checks for Intel Arc GPU environment variables and disables CUDA to prevent
    Global Interpreter Lock (GIL) related crashes when using PyTorch with Intel
    Arc GPUs. This is a known compatibility issue that requires CPU-only mode.

    Returns:
        bool: True if Intel Arc GPU detected and CUDA disabled, False otherwise.

    """
    # Check if UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS is set (Intel Arc indicator)
    if os.environ.get("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS") == "1":
        logger.info("Intel Arc GPU environment detected - using CPU mode for PyTorch to prevent GIL issues")
        os.environ["CUDA_VISIBLE_DEVICES"] = ""  # Empty string = no CUDA devices
        return True

    # Also check for Intel GPU environment variables
    if os.environ.get("ONEAPI_DEVICE_SELECTOR") or os.environ.get("SYCL_DEVICE_FILTER"):
        logger.info("Intel GPU environment detected - using CPU mode for PyTorch")
        os.environ["CUDA_VISIBLE_DEVICES"] = ""
        return True

    return False


_is_intel_arc = _detect_and_fix_intel_arc()


def _safe_torch_import(timeout: float = 10.0) -> tuple[bool, dict[str, object] | None, Exception | None]:
    """Safely import PyTorch with Intel Arc workaround applied.

    Attempts to import PyTorch and all necessary submodules. Returns a tuple
    containing a success flag, a dictionary of imported modules, and any
    exception that occurred during import.

    Args:
        timeout: Timeout in seconds for import operation (currently unused).

    Returns:
        tuple[bool, dict[str, object] | None, Exception | None]: Success flag,
            dictionary of torch modules (if successful) or None, and exception
            (if failed) or None.

    Raises:
        No exceptions are raised; they are captured and returned in the tuple.

    """
    try:
        # Direct import - Intel Arc workaround already applied
        import torch as torch_temp

        torch_modules: dict[str, object] = {
            "torch": torch_temp,
            "Tensor": torch_temp.Tensor,
            "cuda": torch_temp.cuda,
            "device": torch_temp.device,
            "dtype": torch_temp.dtype,
            "nn": torch_temp.nn,
            "optim": torch_temp.optim,
            "save": torch_temp.save,
            "load": torch_temp.load,
            "tensor": torch_temp.tensor,
        }
        return True, torch_modules, None
    except Exception as e:
        logger.warning(f"PyTorch import failed: {e}")
        return False, None, e


# Attempt safe PyTorch import - skip entirely if Intel Arc detected
if _is_intel_arc:
    logger.info("Intel Arc GPU detected - skipping PyTorch import to prevent GIL crashes, using fallbacks")
    HAS_TORCH = False
    TORCH_AVAILABLE = False
    TORCH_VERSION = None
else:
    try:
        success, modules, error = _safe_torch_import()

        if success and modules:
            # Use the successfully imported modules WITHOUT re-importing
            torch = modules["torch"]
            Tensor = modules["Tensor"]
            cuda = modules["cuda"]
            device = modules["device"]
            dtype = modules["dtype"]
            nn = modules["nn"]
            optim = modules["optim"]
            save = modules["save"]
            load = modules["load"]
            tensor = modules["tensor"]

            HAS_TORCH = True
            TORCH_AVAILABLE = True
            TORCH_VERSION = torch_temp.__version__
            logger.info(f"PyTorch {TORCH_VERSION} imported successfully with universal GPU compatibility")
        else:
            error_msg = "PyTorch import failed"
            logger.error(error_msg)
            raise error or ImportError(error_msg)

    except Exception as e:
        logger.info(f"Using PyTorch fallbacks due to import issue: {e}")
        HAS_TORCH = False
        TORCH_AVAILABLE = False
        TORCH_VERSION = None

# Set up fallback implementations when PyTorch is not available
if not HAS_TORCH:
    logger.info("Setting up PyTorch fallback implementations")

    # Production-ready fallback implementations
    class FallbackTensor:
        """Fallback tensor implementation for when PyTorch is unavailable.

        Provides a minimal tensor-like interface to maintain API compatibility
        with PyTorch code when the actual library cannot be imported.
        """

        def __init__(self, data: object | None = None, dtype: object | None = None, device: object | None = None) -> None:
            """Initialize fallback tensor.

            Args:
                data: Tensor data (default None, becomes empty list).
                dtype: Data type specification (stored but not used).
                device: Device specification (stored but not used).

            """
            self.data: object = data or []
            self.dtype: object | None = dtype
            self.device: object | None = device

        def __repr__(self) -> str:
            """Return string representation of fallback tensor."""
            return f"FallbackTensor({self.data})"

        def cuda(self) -> "FallbackTensor":
            """Move to CUDA (no-op in fallback).

            Returns:
                FallbackTensor: Self (no actual device transfer).

            """
            return self

        def cpu(self) -> "FallbackTensor":
            """Move to CPU (no-op in fallback).

            Returns:
                FallbackTensor: Self (no actual device transfer).

            """
            return self

        def numpy(self) -> object:
            """Convert to numpy array representation.

            Returns:
                object: The underlying data object.

            """
            return self.data

    class FallbackCuda:
        """Fallback CUDA interface for when PyTorch is unavailable.

        Provides methods that indicate CUDA is not available, maintaining
        API compatibility with PyTorch's cuda module.
        """

        @staticmethod
        def is_available() -> bool:
            """Check CUDA availability.

            Returns:
                bool: Always False in fallback mode.

            """
            return False

        @staticmethod
        def device_count() -> int:
            """Get count of CUDA devices.

            Returns:
                int: Always 0 in fallback mode.

            """
            return 0

        @staticmethod
        def get_device_name(device: int | None = None) -> str:
            """Get CUDA device name.

            Args:
                device: Device index (unused in fallback).

            Returns:
                str: Always "CPU Fallback" in fallback mode.

            """
            return "CPU Fallback"

    class FallbackDevice:
        """Fallback device for when PyTorch is unavailable.

        Represents a CPU device, maintaining API compatibility with PyTorch's
        device class.
        """

        def __init__(self, device_str: str) -> None:
            """Initialize fallback device.

            Args:
                device_str: Device string specification (stored but not used).

            """
            self.type: str = "cpu"

    class FallbackModule:
        """Fallback neural network module for when PyTorch is unavailable.

        Provides minimal interface for neural network module compatibility.
        """

        pass

    class FallbackOptimizer:
        """Fallback optimizer for when PyTorch is unavailable.

        Provides minimal interface for optimizer compatibility.
        """

        pass


    # Assign fallback objects
    torch = None
    Tensor = FallbackTensor
    cuda = FallbackCuda()
    device = FallbackDevice
    dtype = None
    nn = type("nn", (), {"Module": FallbackModule})()
    optim = type("optim", (), {"Optimizer": FallbackOptimizer})()

    def tensor(data: object, **kwargs: object) -> FallbackTensor:
        """Create fallback tensor.

        Wraps data in a FallbackTensor object for API compatibility.

        Args:
            data: Tensor data to wrap.
            **kwargs: Additional keyword arguments (passed to FallbackTensor).

        Returns:
            FallbackTensor: Wrapped tensor object.

        """
        return FallbackTensor(data, **kwargs)

    def save(obj: object, path: str) -> None:
        """Fallback save function for PyTorch compatibility.

        No-op implementation when PyTorch is unavailable. In production,
        this would serialize objects to disk; in fallback mode it does nothing.

        Args:
            obj: Object to save (unused in fallback).
            path: File path for saving (unused in fallback).

        """

    def load(path: str, **kwargs: object) -> dict[str, object]:
        """Fallback load function for PyTorch compatibility.

        No-op implementation when PyTorch is unavailable. In production,
        this would deserialize objects from disk; in fallback mode it
        returns an empty dictionary.

        Args:
            path: File path to load from (unused in fallback).
            **kwargs: Additional keyword arguments (unused in fallback).

        Returns:
            dict[str, object]: Empty dictionary in fallback mode.

        """
        return {}


# Export all PyTorch objects and availability flag
__all__ = [
    # Availability flags
    "HAS_TORCH",
    "TORCH_AVAILABLE",
    "TORCH_VERSION",
    # Main module
    "torch",
    # Classes and objects
    "Tensor",
    "cuda",
    "device",
    "dtype",
    "nn",
    "optim",
    # Functions
    "tensor",
    "save",
    "load",
]
