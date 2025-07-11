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
Test Intellicrack GPU Integration
Verifies that Intellicrack can use your Intel Arc B580
"""
import os
import sys

print("=" * 60)
print("Testing Intellicrack GPU Integration")
print("=" * 60)

# First check if we're in conda environment
print("\n1. Checking Environment...")
if 'CONDA_PREFIX' in os.environ:
    print(f"✓ Conda environment active: {os.path.basename(os.environ['CONDA_PREFIX'])}")
else:
    print("⚠ Not in a conda environment")
    print("  Run: conda activate intel-gpu")

# Test basic GPU detection
print("\n2. Testing Basic GPU Detection...")
try:
    import torch
    import intel_extension_for_pytorch as ipex
    
    if hasattr(torch, 'xpu') and torch.xpu.is_available():
        print(f"✓ Intel GPU detected: {torch.xpu.get_device_name(0)}")
    else:
        print("✗ Intel GPU not detected")
        sys.exit(1)
except ImportError as e:
    print(f"✗ Required packages not found: {e}")
    sys.exit(1)

# Test Intellicrack import with GPU
print("\n3. Testing Intellicrack GPU Integration...")
try:
    # This should trigger automatic GPU detection
    from intellicrack.utils.gpu_autoloader import get_device, get_gpu_info
    
    device = get_device()
    gpu_info = get_gpu_info()
    
    print(f"✓ Intellicrack GPU autoloader working")
    print(f"  Device: {device}")
    print(f"  GPU Available: {gpu_info['gpu_available']}")
    print(f"  GPU Type: {gpu_info['gpu_type']}")
    if 'gpu_name' in gpu_info:
        print(f"  GPU Name: {gpu_info['gpu_name']}")
    
except ImportError as e:
    print(f"✗ Could not import Intellicrack GPU module: {e}")
    print("\nTrying fallback test...")
    
    # Fallback: Add Intellicrack to path
    intellicrack_path = os.path.dirname(os.path.abspath(__file__))
    if intellicrack_path not in sys.path:
        sys.path.insert(0, intellicrack_path)
    
    try:
        from intellicrack.utils.gpu_autoloader import get_device, get_gpu_info
        print("✓ Intellicrack GPU module loaded with path adjustment")
    except:
        print("✗ Could not load Intellicrack GPU module")

# Test GPU acceleration
print("\n4. Testing GPU Acceleration...")
try:
    from intellicrack.ai.gpu_integration import GPUAcceleratedModel, create_gpu_model
    
    # Simple test model
    import torch.nn as nn
    
    class TestModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.linear = nn.Linear(100, 10)
        
        def forward(self, x):
            return self.linear(x)
    
    # Create model with GPU acceleration
    model = create_gpu_model(TestModel)
    
    # Check device
    param_device = next(model.parameters()).device
    print(f"✓ Model created on: {param_device}")
    
    # Test inference
    test_input = torch.randn(32, 100)
    output = model(test_input.to(param_device))
    
    print(f"✓ Inference successful")
    print(f"  Input shape: {test_input.shape}")
    print(f"  Output shape: {output.shape}")
    print(f"  Output device: {output.device}")
    
except Exception as e:
    print(f"✗ GPU acceleration test failed: {e}")

# Test memory reporting
print("\n5. Testing Memory Reporting...")
try:
    if torch.xpu.is_available():
        allocated = torch.xpu.memory_allocated('xpu:0') / 1024**2
        reserved = torch.xpu.memory_reserved('xpu:0') / 1024**2
        
        print(f"✓ Memory stats available")
        print(f"  Allocated: {allocated:.2f} MB")
        print(f"  Reserved: {reserved:.2f} MB")
except:
    print("✗ Could not get memory stats")

# Summary
print("\n" + "=" * 60)
print("Summary:")
print("=" * 60)

successes = []
failures = []

# Check each component
checks = {
    "Conda environment": 'CONDA_PREFIX' in os.environ,
    "Intel GPU detection": 'gpu_info' in locals() and gpu_info.get('gpu_available', False),
    "Intellicrack GPU module": 'get_device' in locals(),
    "GPU acceleration": 'output' in locals(),
    "Memory reporting": 'allocated' in locals()
}

for name, success in checks.items():
    if success:
        successes.append(name)
        print(f"✓ {name}")
    else:
        failures.append(name)
        print(f"✗ {name}")

print(f"\nPassed: {len(successes)}/{len(checks)}")

if len(successes) == len(checks):
    print("\n🎉 All tests passed! Your Intel Arc B580 is ready for Intellicrack!")
else:
    print(f"\n⚠ Some tests failed. Please check:")
    for failure in failures:
        print(f"  - {failure}")

print("\n" + "=" * 60)