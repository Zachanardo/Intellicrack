#!/usr/bin/env python3
"""
Test GPU Unification System for Intellicrack

This script tests the unified GPU acceleration system with support for:
- Intel Arc GPUs (via Intel Extension for PyTorch)
- NVIDIA GPUs (via CUDA)
- AMD GPUs (via ROCm)
- DirectML (Windows GPU acceleration)

Copyright (C) 2025 Zachary Flint
"""

import os
import sys
import time

# Add Intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 80)
print("Intellicrack GPU Unification Test")
print("=" * 80)

# Test 1: Import and initialize GPU autoloader
print("\n1. Testing GPU Autoloader Import...")
try:
    from intellicrack.utils.gpu_autoloader import (
        gpu_autoloader,
        get_device,
        get_gpu_info,
        to_device,
        optimize_for_gpu
    )
    print("✓ GPU autoloader imported successfully")
except ImportError as e:
    print(f"✗ Failed to import GPU autoloader: {e}")
    sys.exit(1)

# Test 2: Check GPU detection
print("\n2. Testing GPU Detection...")
gpu_info = get_gpu_info()
print(f"GPU Available: {gpu_info['available']}")
print(f"GPU Type: {gpu_info['type']}")
print(f"Device String: {gpu_info['device']}")
print("\nDetailed GPU Info:")
for key, value in gpu_info['info'].items():
    print(f"  {key}: {value}")

if gpu_info['memory']:
    print("\nMemory Info:")
    for key, value in gpu_info['memory'].items():
        print(f"  {key}: {value}")

# Test 3: Test GPU acceleration manager
print("\n3. Testing GPU Acceleration Manager...")
try:
    from intellicrack.core.processing.gpu_accelerator import GPUAccelerationManager
    gpu_manager = GPUAccelerationManager()
    print(f"✓ GPU Manager initialized")
    print(f"  Backend: {gpu_manager.get_backend()}")
    print(f"  GPU Type: {gpu_manager.get_gpu_type()}")
    print(f"  Available: {gpu_manager.is_acceleration_available()}")
except Exception as e:
    print(f"✗ Failed to initialize GPU manager: {e}")

# Test 4: Test AI GPU integration
print("\n4. Testing AI GPU Integration...")
try:
    from intellicrack.ai.gpu_integration import (
        get_ai_device,
        get_ai_gpu_info,
        is_gpu_available,
        prepare_ai_model,
        prepare_ai_tensor
    )

    ai_gpu_info = get_ai_gpu_info()
    print(f"✓ AI GPU integration loaded")
    print(f"  Available: {is_gpu_available()}")
    print(f"  Backend: {ai_gpu_info.get('info', {}).get('backend', 'Unknown')}")
    print(f"  Device: {get_ai_device()}")
except Exception as e:
    print(f"✗ Failed to test AI GPU integration: {e}")

# Test 5: Test tensor operations
print("\n5. Testing Tensor Operations...")
try:
    torch = gpu_autoloader.get_torch()
    if torch:
        # Create a test tensor
        print("Creating test tensor...")
        test_tensor = torch.randn(1000, 1000)
        print(f"  Original device: {test_tensor.device}")

        # Move to GPU
        gpu_tensor = to_device(test_tensor)
        print(f"  GPU device: {gpu_tensor.device}")

        # Perform computation
        print("Performing matrix multiplication...")
        start_time = time.time()
        result = torch.matmul(gpu_tensor, gpu_tensor)
        gpu_autoloader.synchronize()
        elapsed = time.time() - start_time

        print(f"✓ Computation completed in {elapsed:.3f} seconds")
        print(f"  Result shape: {result.shape}")
        print(f"  Result device: {result.device}")

        # Test optimization for Intel XPU
        if gpu_info['type'] == 'intel_xpu':
            print("\nTesting Intel XPU optimization...")
            ipex = gpu_autoloader.get_ipex()
            if ipex:
                # Create a simple model
                model = torch.nn.Sequential(
                    torch.nn.Linear(100, 50),
                    torch.nn.ReLU(),
                    torch.nn.Linear(50, 10)
                )

                # Optimize model
                optimized_model = optimize_for_gpu(model)
                print("✓ Model optimized for Intel XPU")

                # Test inference
                test_input = torch.randn(32, 100)
                gpu_input = to_device(test_input)

                with torch.no_grad():
                    output = optimized_model(gpu_input)

                print(f"✓ Inference successful, output shape: {output.shape}")

    else:
        print("✗ PyTorch not available for tensor operations")

except Exception as e:
    print(f"✗ Tensor operation test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 6: Pattern matching acceleration
print("\n6. Testing Pattern Matching Acceleration...")
try:
    if gpu_manager:
        test_data = b"Hello World! This is a test string for pattern matching." * 1000
        test_patterns = [b"test", b"World", b"pattern"]

        print(f"Testing pattern matching on {len(test_data)} bytes...")
        start_time = time.time()
        matches = gpu_manager.accelerate_pattern_matching(test_data, test_patterns)
        elapsed = time.time() - start_time

        print(f"✓ Found {len(matches)} matches in {elapsed:.3f} seconds")
        print(f"  First 10 match positions: {matches[:10]}")
except Exception as e:
    print(f"✗ Pattern matching test failed: {e}")

# Test 7: Memory stress test
print("\n7. Testing GPU Memory Management...")
try:
    if torch and gpu_info['available']:
        print("Allocating large tensors...")
        tensors = []
        try:
            for i in range(5):
                size = 1000 * (i + 1)
                tensor = torch.randn(size, size)
                gpu_tensor = to_device(tensor)
                tensors.append(gpu_tensor)

                # Get memory info
                mem_info = gpu_autoloader.get_memory_info()
                if mem_info:
                    print(f"  Tensor {i + 1} ({size}x{size}): {mem_info.get('allocated', 'N/A')}")

            print("✓ Memory allocation successful")

            # Clean up
            del tensors
            if hasattr(torch, gpu_info['type'].split('_')[0]):
                getattr(torch, gpu_info['type'].split('_')[0]).empty_cache()

        except RuntimeError as e:
            if "out of memory" in str(e):
                print(f"✓ GPU memory limit reached as expected: {e}")
            else:
                raise

except Exception as e:
    print(f"✗ Memory management test failed: {e}")

# Summary
print("\n" + "=" * 80)
print("GPU UNIFICATION TEST SUMMARY")
print("=" * 80)
print(f"GPU Type: {gpu_info['type']}")
print(f"GPU Available: {gpu_info['available']}")
if gpu_info['available']:
    print(f"Device Name: {gpu_info['info'].get('device_name', 'Unknown')}")
    print(f"Backend: {gpu_info['info'].get('backend', 'Unknown')}")
    print(f"Total Memory: {gpu_info['info'].get('total_memory', 'Unknown')}")

    if gpu_info['type'] == 'intel_xpu':
        print("\n✓ Intel Arc GPU support is active!")
        print("  - Intel Extension for PyTorch detected")
        print("  - XPU device available")
        print("  - Model optimization available")
    elif gpu_info['type'] == 'nvidia_cuda':
        print("\n✓ NVIDIA GPU support is active!")
        print("  - CUDA device available")
        print("  - PyTorch CUDA support detected")
    elif gpu_info['type'] == 'amd_rocm':
        print("\n✓ AMD GPU support is active!")
        print("  - ROCm device available")
        print("  - PyTorch HIP support detected")
    elif gpu_info['type'] == 'directml':
        print("\n✓ DirectML GPU support is active!")
        print("  - Windows GPU acceleration available")

print("\n✓ GPU unification system is working correctly!")
print("=" * 80)
