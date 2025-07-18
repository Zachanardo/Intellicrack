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
Intel Arc B580 Performance Benchmark
Tests the computational performance of your GPU
"""
import torch
import intel_extension_for_pytorch as ipex
import time
import sys

print("=" * 70)
print("Intel Arc B580 Performance Benchmark")
print("=" * 70)

# Check if XPU is available
if not (hasattr(torch, 'xpu') and torch.xpu.is_available()):
    print("Error: Intel GPU not available!")
    print("Please run test_intel_gpu.py first to diagnose the issue.")
    sys.exit(1)

# Get device
device = torch.device('xpu:0')
device_name = torch.xpu.get_device_name(0)
props = torch.xpu.get_device_properties(0)

print(f"\nGPU Information:")
print(f"Device: {device_name}")
print(f"Total Memory: {props.total_memory / 1024**3:.1f} GB")
print(f"Driver Version: {props.driver_version}")

# Benchmark settings
print("\nBenchmark Configuration:")
print("Operation: Matrix Multiplication (GEMM)")
print("Precision: FP32")
print("Warmup iterations: 5")
print("Benchmark iterations: 20")

# Test different matrix sizes
matrix_sizes = [1024, 2048, 4096, 8192]
results = []

print("\n" + "-" * 70)
print(f"{'Size':>8} | {'Time (s)':>10} | {'TFLOPS':>10} | {'Memory (GB)':>12} | {'GB/s':>10}")
print("-" * 70)

for size in matrix_sizes:
    # Skip very large sizes if not enough memory
    required_memory = (3 * size * size * 4) / 1024**3  # 3 matrices, 4 bytes per float
    if required_memory > props.total_memory / 1024**3 * 0.8:
        print(f"{size:>8} | {'SKIPPED - Not enough memory':>45}")
        continue

    try:
        # Create matrices
        a = torch.randn(size, size, device=device, dtype=torch.float32)
        b = torch.randn(size, size, device=device, dtype=torch.float32)

        # Warmup
        for _ in range(5):
            c = torch.matmul(a, b)
        torch.xpu.synchronize()

        # Benchmark
        torch.xpu.synchronize()
        start_time = time.time()

        iterations = 20 if size <= 4096 else 10
        for _ in range(iterations):
            c = torch.matmul(a, b)

        torch.xpu.synchronize()
        end_time = time.time()

        # Calculate metrics
        elapsed_time = end_time - start_time
        flops = 2 * size**3 * iterations  # 2*n^3 operations for matrix multiply
        tflops = flops / elapsed_time / 1e12

        # Memory bandwidth (approximate)
        bytes_accessed = 3 * size * size * 4 * iterations  # Read A, B, write C
        bandwidth = bytes_accessed / elapsed_time / 1e9

        # Current memory usage
        memory_used = torch.xpu.memory_allocated(device) / 1024**3

        print(f"{size:>8} | {elapsed_time:>10.3f} | {tflops:>10.2f} | {memory_used:>12.2f} | {bandwidth:>10.1f}")

        results.append({
            'size': size,
            'time': elapsed_time,
            'tflops': tflops,
            'memory': memory_used,
            'bandwidth': bandwidth
        })

        # Clean up
        del a, b, c
        torch.xpu.empty_cache()

    except Exception as e:
        print(f"{size:>8} | ERROR: {str(e)[:40]}")

print("-" * 70)

# Summary
if results:
    avg_tflops = sum(r['tflops'] for r in results) / len(results)
    print(f"\nAverage Performance: {avg_tflops:.2f} TFLOPS")

    # Performance rating
    print("\nPerformance Analysis:")
    if avg_tflops > 20:
        print("✓ Excellent! Your Intel Arc B580 is performing very well.")
    elif avg_tflops > 15:
        print("✓ Good performance from your Intel Arc B580.")
    elif avg_tflops > 10:
        print("✓ Decent performance. Check if GPU boost is active.")
    else:
        print("⚠ Lower than expected performance. Check drivers and cooling.")

# Memory bandwidth test
print("\n" + "=" * 70)
print("Memory Bandwidth Test")
print("=" * 70)

size = 64 * 1024 * 1024  # 64M elements
try:
    # Create large array
    x = torch.randn(size, device=device, dtype=torch.float32)
    y = torch.randn(size, device=device, dtype=torch.float32)

    # Warmup
    for _ in range(5):
        z = x + y
    torch.xpu.synchronize()

    # Benchmark
    iterations = 100
    start_time = time.time()

    for _ in range(iterations):
        z = x + y

    torch.xpu.synchronize()
    end_time = time.time()

    # Calculate bandwidth
    elapsed_time = end_time - start_time
    bytes_transferred = 3 * size * 4 * iterations  # Read x, y, write z
    bandwidth = bytes_transferred / elapsed_time / 1e9

    print(f"Memory Bandwidth: {bandwidth:.1f} GB/s")
    print(f"Theoretical Max: ~400-450 GB/s for Arc B580")
    print(f"Efficiency: {bandwidth / 450 * 100:.1f}%")

except Exception as e:
    print(f"Memory bandwidth test failed: {e}")

print("\n" + "=" * 70)
print("Benchmark Complete!")
print("=" * 70)
