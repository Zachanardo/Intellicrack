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

"""Test GPU detection functionality."""

import os
import sys
from pathlib import Path

# Add the intellicrack package to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the detection function
from launch_intellicrack import detect_and_configure_gpu

print("Testing GPU Detection...")
print("=" * 60)

# Run detection
gpu_detected, gpu_type, gpu_vendor = detect_and_configure_gpu()

print("\n" + "=" * 60)
print("DETECTION RESULTS:")
print("=" * 60)
print(f"GPU Detected: {gpu_detected}")
print(f"GPU Type: {gpu_type}")
print(f"GPU Vendor: {gpu_vendor}")

print("\n" + "=" * 60)
print("CONFIGURED ENVIRONMENT VARIABLES:")
print("=" * 60)

# Check key environment variables
env_vars = [
    'QT_OPENGL',
    'QT_ANGLE_PLATFORM',
    'QSG_RENDER_LOOP',
    'SYCL_DEVICE_FILTER',
    'INTEL_COMPUTE_BACKEND',
    'CUDA_CACHE_DISABLE',
    'HSA_ENABLE_SDMA',
    'MKL_SERVICE_FORCE_INTEL',
    'OMP_NUM_THREADS'
]

for var in env_vars:
    value = os.environ.get(var, '<not set>')
    if value != '<not set>':
        print(f"{var}: {value}")

print("\nTest completed!")
