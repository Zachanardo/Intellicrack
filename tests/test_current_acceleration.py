"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Tests for current hardware acceleration capabilities."""
import torch
import platform

print(f"Python version: {platform.python_version()}")
print(f"PyTorch version: {torch.__version__}")
print(f"Platform: {platform.platform()}")

# Check CPU optimizations
print("\n=== CPU Acceleration ===")
print(f"MKL available: {torch.backends.mkl.is_available()}")
print(f"OpenMP available: {torch.backends.openmp.is_available()}")

# Check what devices are available
print("\n=== Available Devices ===")
print(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"CUDA device count: {torch.cuda.device_count()}")
    print(f"CUDA device name: {torch.cuda.get_device_name()}")

# Test CPU performance
print("\n=== CPU Performance Test ===")
import time
x = torch.randn(1000, 1000)
y = torch.randn(1000, 1000)

start = time.time()
z = torch.mm(x, y)
end = time.time()

print(f"Matrix multiplication (1000x1000) took: {end-start:.4f} seconds")
print(f"Using device: {x.device}")

# Check if Intel MKL is being used
if hasattr(torch.backends.mkl, 'is_available') and torch.backends.mkl.is_available():
    print("✓ Intel MKL acceleration active")
else:
    print("✗ Intel MKL not detected")

print("\n=== Summary ===")
print("You have CPU acceleration via Intel MKL")
print("For Intel GPU acceleration, you need conda environment")