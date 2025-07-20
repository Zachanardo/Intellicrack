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

"""Tests for Intel GPU acceleration capabilities."""
import torch

print(f"XPU available: {torch.xpu.is_available()}")
print(f"XPU device count: {torch.xpu.device_count()}")

if torch.xpu.is_available():
    print(f"XPU device name: {torch.xpu.get_device_name()}")
    
    # Test tensor operation on GPU
    x = torch.randn(3, 3).to('xpu')
    y = torch.randn(3, 3).to('xpu')
    z = torch.mm(x, y)
    print("✓ Intel GPU tensor operations working!")
    print(f"Result shape: {z.shape}")
else:
    print("✗ Intel GPU not detected")
    print("Using CPU fallback")