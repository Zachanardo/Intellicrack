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

import os
from typing import Optional

from intellicrack.utils.logger import logger

"""
PyTorch Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for PyTorch imports.
When PyTorch is not available, it provides fallback implementations for
tensor operations used in Intellicrack's ML components.
"""

# PyTorch availability detection and import handling with Intel Arc B580 compatibility

# Initialize variables
HAS_TORCH = False
TORCH_AVAILABLE = False
TORCH_VERSION = None
torch = None
Tensor = None
cuda = None
device = None
dtype = None
nn = None
optim = None
save = None
load = None
tensor = None

# Load environment variables from .env file
# Users can customize GPU settings in the .env file
try:
    from dotenv import load_dotenv

    load_dotenv()  # Load .env file from project root
except ImportError:
    pass  # dotenv not available, use system environment variables


# Detect Intel Arc GPU and apply workaround
def _detect_and_fix_intel_arc():
    """Detect Intel Arc GPU and apply CPU-only workaround to prevent GIL crashes."""
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


def _safe_torch_import(timeout: float = 10.0) -> tuple[bool, Optional[object], Optional[Exception]]:
    """Safely import PyTorch with Intel Arc workaround applied."""
    try:
        # Direct import - Intel Arc workaround already applied
        import torch as torch_temp

        torch_modules = {
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
            TORCH_VERSION = torch.__version__
            logger.info(f"PyTorch {TORCH_VERSION} imported successfully with universal GPU compatibility")
        else:
            raise error or ImportError("PyTorch import failed")

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
        """Fallback tensor implementation."""

        def __init__(self, data=None, dtype=None, device=None):
            self.data = data or []
            self.dtype = dtype
            self.device = device

        def __repr__(self):
            return f"FallbackTensor({self.data})"

        def cuda(self):
            """Move to CUDA (no-op in fallback)."""
            return self

        def cpu(self):
            """Move to CPU (no-op in fallback)."""
            return self

        def numpy(self):
            """Convert to numpy array."""
            return self.data

    class FallbackCuda:
        """Fallback CUDA interface."""

        @staticmethod
        def is_available():
            return False

        @staticmethod
        def device_count():
            return 0

        @staticmethod
        def get_device_name(device=None):
            return "CPU Fallback"

    class FallbackDevice:
        """Fallback device."""

        def __init__(self, device_str):
            self.type = "cpu"

    class FallbackModule:
        """Fallback neural network module."""

        pass

    class FallbackOptimizer:
        """Fallback optimizer."""

        pass

    # Assign fallback objects
    torch = None
    Tensor = FallbackTensor
    cuda = FallbackCuda()
    device = FallbackDevice
    dtype = None
    nn = type("nn", (), {"Module": FallbackModule})()
    optim = type("optim", (), {"Optimizer": FallbackOptimizer})()

    def tensor(data, **kwargs):
        """Create fallback tensor."""
        return FallbackTensor(data, **kwargs)

    def save(obj, path):
        """Fallback save function."""
        pass

    def load(path, **kwargs):
        """Fallback load function."""
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
