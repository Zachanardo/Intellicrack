import torch
import intel_extension_for_pytorch as ipex

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