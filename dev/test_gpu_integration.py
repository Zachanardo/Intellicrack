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
Test GPU integration in Intellicrack
This demonstrates automatic GPU detection and usage
"""

print("=== Testing Intellicrack GPU Integration ===\n")

# When importing intellicrack, GPU is automatically initialized
import intellicrack
from intellicrack.utils.gpu_autoloader import get_gpu_info, get_device
from intellicrack.ai.gpu_integration import GPUAcceleratedModel, create_gpu_model, run_on_gpu

# Check GPU status
gpu_info = get_gpu_info()
print(f"GPU Available: {gpu_info['gpu_available']}")
print(f"GPU Type: {gpu_info['gpu_type']}")
if gpu_info.get('gpu_name'):
    print(f"GPU Name: {gpu_info['gpu_name']}")
print(f"Device: {get_device()}")
print()

# Test with a simple model
try:
    import torch
    import torch.nn as nn
    
    # Define a simple model
    class SimpleModel(nn.Module):
        def __init__(self):
            super().__init__()
            self.linear = nn.Linear(100, 10)
            
        def forward(self, x):
            return self.linear(x)
    
    # Create model with automatic GPU acceleration
    print("Creating model with automatic GPU acceleration...")
    model = create_gpu_model(SimpleModel)
    print(f"Model device: {next(model.parameters()).device}")
    
    # Test inference with automatic GPU placement
    @run_on_gpu
    def test_inference(model, data):
        with torch.no_grad():
            return model(data)
    
    # Create test data (automatically moved to GPU)
    test_data = torch.randn(32, 100)
    output = test_inference(model, test_data)
    print(f"Output shape: {output.shape}")
    print(f"Output device: {output.device}")
    
    # Test GPUAcceleratedModel wrapper
    print("\nTesting GPUAcceleratedModel wrapper...")
    gpu_model = GPUAcceleratedModel(SimpleModel())
    print(f"Is GPU accelerated: {gpu_model.is_gpu_accelerated}")
    
    memory = gpu_model.get_memory_usage()
    if memory:
        print(f"Memory allocated: {memory['allocated']:.2f} MB")
        print(f"Memory reserved: {memory['reserved']:.2f} MB")
    
except ImportError as e:
    print(f"PyTorch not available: {e}")
except Exception as e:
    print(f"Error during test: {e}")

print("\n=== GPU Integration Test Complete ===")

# Example of how this would be used in Intellicrack modules:
print("\nExample usage in Intellicrack:")
print("""
# In any AI module:
from intellicrack.ai.gpu_integration import create_gpu_model, run_on_gpu

# Model automatically uses GPU if available
model = create_gpu_model(YourModelClass, config)

# Functions automatically run on GPU
@run_on_gpu
def process_binary(model, binary_data):
    return model.analyze(binary_data)
""")