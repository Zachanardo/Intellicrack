#!/usr/bin/env python
"""Test importing handlers directly."""

import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")

print("Testing handler imports...")

try:
    print("\n1. Testing tensorflow_handler import...")
    from intellicrack.handlers import tensorflow_handler
    print(f"   ✓ TensorFlow handler imported")
    print(f"   - HAS_TENSORFLOW: {tensorflow_handler.HAS_TENSORFLOW}")
    print(f"   - TF_AVAILABLE: {tensorflow_handler.TF_AVAILABLE}")
    
    print("\n2. Testing torch_handler import...")
    from intellicrack.handlers import torch_handler
    print(f"   ✓ PyTorch handler imported")
    print(f"   - HAS_TORCH: {torch_handler.HAS_TORCH}")
    print(f"   - TORCH_AVAILABLE: {torch_handler.TORCH_AVAILABLE}")
    
    print("\n3. Testing torch_gil_safety import...")
    from intellicrack.utils import torch_gil_safety
    print(f"   ✓ Torch GIL safety imported")
    
    print("\n4. Testing safe_torch_import...")
    torch = torch_gil_safety.safe_torch_import()
    print(f"   ✓ safe_torch_import returned: {torch}")
    
    print("\n✅ All handler imports successful!")
    
except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)