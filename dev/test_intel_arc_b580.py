#!/usr/bin/env python3
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

"""
Intel Arc B580 GPU Test for Intellicrack

Quick test to verify Intel Arc B580 works with the unified GPU system.
"""

import os
import sys

# Add Intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Intel Arc B580 GPU Test for Intellicrack")
print("=" * 60)

# Import and test
try:
    from intellicrack.utils.gpu_autoloader import get_gpu_info, get_device, to_device
    
    # Get GPU info
    gpu_info = get_gpu_info()
    
    print(f"\nGPU Detected: {gpu_info['available']}")
    print(f"GPU Type: {gpu_info['type']}")
    print(f"Device: {gpu_info['device']}")
    
    if gpu_info['available'] and 'intel' in gpu_info['type']:
        print("\n✓ Intel GPU detected!")
        print(f"Device Name: {gpu_info['info'].get('device_name', 'Unknown')}")
        print(f"Total Memory: {gpu_info['info'].get('total_memory', 'Unknown')}")
        
        # Test tensor operations
        import torch
        print("\nTesting tensor operations...")
        
        # Create test tensor
        x = torch.randn(1000, 1000)
        print(f"Created tensor on: {x.device}")
        
        # Move to GPU
        x_gpu = to_device(x)
        print(f"Moved tensor to: {x_gpu.device}")
        
        # Perform operation
        y = torch.matmul(x_gpu, x_gpu)
        print(f"Matrix multiplication result shape: {y.shape}")
        print(f"Result device: {y.device}")
        
        print("\n✓ Intel Arc B580 is working with Intellicrack!")
        
    else:
        print("\n✗ Intel GPU not detected")
        print("Make sure:")
        print("1. Intel GPU drivers are installed")
        print("2. Intel Extension for PyTorch is installed")
        print("3. You're using the conda environment with IPEX")
        
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)