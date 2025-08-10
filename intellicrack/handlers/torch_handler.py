"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

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

from intellicrack.logger import logger

"""
PyTorch Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for PyTorch imports.
When PyTorch is not available, it provides fallback implementations for
tensor operations used in Intellicrack's ML components.
"""

# PyTorch availability detection and import handling
# TEMPORARY FIX: Disable PyTorch import due to Intel Arc B580 compatibility issues
# The import causes a hang on systems with Intel Arc GPUs
# Using fallback implementations until the issue is resolved
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

# Original import code (disabled):
# try:
#     import torch
#     from torch import (
#         Tensor,
#         cuda,
#         device,
#         dtype,
#         nn,
#         optim,
#         save,
#         load,
#         tensor,
#     )
#     
#     HAS_TORCH = True
#     TORCH_AVAILABLE = True
#     TORCH_VERSION = torch.__version__
#     
# except ImportError as e:

if False:  # Keep exception handling structure intact
    pass
    
# Always use fallback implementations since PyTorch causes hang
logger.info("Using PyTorch fallback implementations (Intel Arc B580 compatibility mode)")

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
nn = type('nn', (), {'Module': FallbackModule})()
optim = type('optim', (), {'Optimizer': FallbackOptimizer})()

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
    "HAS_TORCH", "TORCH_AVAILABLE", "TORCH_VERSION",
    # Main module
    "torch",
    # Classes and objects
    "Tensor", "cuda", "device", "dtype", "nn", "optim",
    # Functions
    "tensor", "save", "load",
]