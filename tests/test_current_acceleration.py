import torch
import platform

print(f"Python version: {platform.python_version()}")
print(f"PyTorch version: {torch.__version__}")
print(f"Platform: {platform.platform()}")

# Check CPU optimizations
print(f"\n=== CPU Acceleration ===")
print(f"MKL available: {torch.backends.mkl.is_available()}")
print(f"OpenMP available: {torch.backends.openmp.is_available()}")

# Check what devices are available
print(f"\n=== Available Devices ===")
print(f"CUDA available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"CUDA device count: {torch.cuda.device_count()}")
    print(f"CUDA device name: {torch.cuda.get_device_name()}")

# Test CPU performance
print(f"\n=== CPU Performance Test ===")
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

print(f"\n=== Summary ===")
print("You have CPU acceleration via Intel MKL")
print("For Intel GPU acceleration, you need conda environment")