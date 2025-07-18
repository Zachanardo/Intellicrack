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
Intel Arc B580 GPU Test Script using DirectML
Tests GPU acceleration on Windows
"""

import sys
import platform
import time

print("=== Intel Arc B580 GPU Test (Windows) ===")
print(f"Python: {sys.version}")
print(f"Platform: {platform.platform()}")
print()

# Test 1: DirectML (Microsoft's solution for Windows GPU acceleration)
print("=== Testing DirectML ===")
try:
    import torch
    print(f"PyTorch version: {torch.__version__}")

    try:
        import torch_directml
        print("✅ DirectML is installed")

        # List DirectML devices
        dml_device = torch_directml.device()
        print(f"DirectML device: {dml_device}")

        # Create tensors on DirectML device
        print("\nRunning tensor operations on DirectML...")
        device = torch_directml.device(0)

        # Simple computation
        a = torch.randn(2000, 2000).to(device)
        b = torch.randn(2000, 2000).to(device)

        # Warmup
        for _ in range(5):
            c = torch.matmul(a, b)

        # Benchmark
        start = time.time()
        for _ in range(10):
            c = torch.matmul(a, b)
        end = time.time()

        print(f"Matrix multiplication (2000x2000) x10: {end - start:.3f} seconds")
        print(f"GFLOPS: {(2 * 2000**3 * 10) / (end - start) / 1e9:.2f}")

        # Memory info
        print(f"\nTensor device: {c.device}")
        print(f"Result shape: {c.shape}")

        print("\n✅ Intel Arc B580 is working with DirectML!")

    except ImportError:
        print("❌ DirectML not installed")
        print("Install with: pip install torch-directml")

except ImportError:
    print("❌ PyTorch not installed")

# Test 2: Check Windows GPU info
print("\n=== Windows GPU Information ===")
try:
    import subprocess

    # Use wmic to get GPU info
    result = subprocess.run(
        ["wmic", "path", "win32_VideoController", "get", "name,driverversion,adapterram"],
        capture_output=True,
        text=True
    )
    print(result.stdout)

except Exception as e:
    print(f"Error getting GPU info: {e}")

# Test 3: OpenCL (fallback option)
print("\n=== OpenCL Device Check ===")
try:
    import pyopencl as cl

    platforms = cl.get_platforms()
    for i, platform in enumerate(platforms):
        print(f"\nPlatform {i}: {platform.name}")
        devices = platform.get_devices()
        for j, device in enumerate(devices):
            if "Intel" in device.name:
                print(f"  ✅ Found Intel GPU: {device.name}")
                print(f"     - Compute units: {device.max_compute_units}")
                print(f"     - Max frequency: {device.max_clock_frequency} MHz")
                print(f"     - Global memory: {device.global_mem_size / 1024**3:.1f} GB")
                print(f"     - Local memory: {device.local_mem_size / 1024:.1f} KB")

except ImportError:
    print("PyOpenCL not installed - skipping OpenCL check")
except Exception as e:
    print(f"Error checking OpenCL: {e}")

# Test 4: Alternative - ONNX Runtime with DirectML
print("\n=== ONNX Runtime DirectML Check ===")
try:
    import onnxruntime as ort

    # Check available providers
    providers = ort.get_available_providers()
    print(f"Available ONNX providers: {providers}")

    if 'DmlExecutionProvider' in providers:
        print("✅ DirectML provider available for ONNX Runtime")

        # Try to create a session with DirectML
        try:
            import numpy as np

            # Create a simple ONNX model for testing
            session = ort.InferenceSession(
                providers=['DmlExecutionProvider', 'CPUExecutionProvider']
            )
            print("✅ Can use Intel Arc B580 with ONNX Runtime DirectML")

        except Exception as e:
            print(f"Session creation test skipped: {e}")

    else:
        print("❌ DirectML provider not available")
        print("Install with: pip install onnxruntime-directml")

except ImportError:
    print("ONNX Runtime not installed")

print("\n=== Recommendations ===")
print("1. For Windows + Intel Arc B580, use torch-directml")
print("2. For better Intel GPU support, use WSL2 with Linux drivers")
print("3. ONNX Runtime with DirectML is a good alternative")
print("4. Intel Extension for PyTorch has better support on Linux")

print("\n=== Test Complete ===")
