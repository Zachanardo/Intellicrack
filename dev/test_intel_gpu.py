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
Intel Arc B580 GPU Detection Test
Tests if Intel Extension for PyTorch is working correctly
"""
import sys
import platform

print("=" * 60)
print("Intel Arc B580 GPU Detection Test")
print("=" * 60)

# System info
print(f"\nSystem Information:")
print(f"Python: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"Architecture: {platform.machine()}")

# Test PyTorch
print("\n1. Testing PyTorch Installation...")
try:
    import torch
    print(f"✓ PyTorch version: {torch.__version__}")
except ImportError as e:
    print(f"✗ PyTorch not installed: {e}")
    sys.exit(1)

# Test Intel Extension
print("\n2. Testing Intel Extension for PyTorch...")
try:
    import intel_extension_for_pytorch as ipex
    print(f"✓ IPEX version: {ipex.__version__}")
except ImportError as e:
    print(f"✗ Intel Extension not installed: {e}")
    sys.exit(1)

# Test XPU availability
print("\n3. Checking Intel GPU (XPU) Support...")
if hasattr(torch, 'xpu'):
    print("✓ XPU support available in PyTorch")
    
    if torch.xpu.is_available():
        print("✓ Intel GPU is available!")
        
        # Get device info
        device_count = torch.xpu.device_count()
        print(f"\n4. Intel GPU Information:")
        print(f"   Number of GPUs: {device_count}")
        
        for i in range(device_count):
            device_name = torch.xpu.get_device_name(i)
            print(f"   GPU {i}: {device_name}")
            
            # Get properties
            props = torch.xpu.get_device_properties(i)
            print(f"   - Total Memory: {props.total_memory / 1024**3:.1f} GB")
            print(f"   - Driver Version: {props.driver_version}")
            
        # Simple computation test
        print("\n5. Running Simple Computation Test...")
        try:
            device = torch.device('xpu:0')
            
            # Create small tensors
            x = torch.randn(1000, 1000, device=device)
            y = torch.randn(1000, 1000, device=device)
            
            # Perform computation
            z = torch.matmul(x, y)
            torch.xpu.synchronize()
            
            print("✓ Computation test passed!")
            print(f"   Result shape: {z.shape}")
            print(f"   Result device: {z.device}")
            
            # Memory info
            allocated = torch.xpu.memory_allocated(device) / 1024**2
            reserved = torch.xpu.memory_reserved(device) / 1024**2
            print(f"\n6. Memory Usage:")
            print(f"   Allocated: {allocated:.2f} MB")
            print(f"   Reserved: {reserved:.2f} MB")
            
        except Exception as e:
            print(f"✗ Computation test failed: {e}")
            
    else:
        print("✗ Intel GPU not detected by PyTorch XPU")
        print("\nPossible reasons:")
        print("1. Intel GPU drivers not installed or outdated")
        print("2. Windows version not compatible (need Windows 10 21H2+)")
        print("3. GPU not supported by Intel Extension for PyTorch")
        
else:
    print("✗ XPU support not found in PyTorch")
    print("This PyTorch build may not support Intel GPUs")

print("\n" + "=" * 60)
print("Test Complete")
print("=" * 60)