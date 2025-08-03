#!/usr/bin/env python
"""Test PyTorch and TensorFlow interaction"""

import os
import sys

# Configure TensorFlow first
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

print("[TEST] Testing PyTorch + TensorFlow interaction...")

print("\n[1] Importing PyTorch first...", flush=True)
import torch
print(f"✓ PyTorch {torch.__version__} imported")
print(f"  CUDA available: {torch.cuda.is_available()}")

print("\n[2] Now importing TensorFlow...", flush=True)
print("  (This is where it might hang)", flush=True)
import tensorflow as tf
print(f"✓ TensorFlow {tf.__version__} imported")

print("\n[TEST] Both libraries imported successfully!")
print("[TEST] The issue is the interaction between PyTorch and TensorFlow")
