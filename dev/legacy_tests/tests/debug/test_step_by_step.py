#!/usr/bin/env python
"""Step-by-step import test"""

import os
import sys

# Configure TensorFlow first
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

print("[STEP] Testing individual imports...")

# Test basic imports
print("\n[STEP 1] Testing logging...", flush=True)
import logging
print("✓ logging imported")

print("\n[STEP 2] Testing struct...", flush=True)
import struct
print("✓ struct imported")

print("\n[STEP 3] Testing numpy...", flush=True)
import numpy as np
print(f"✓ numpy {np.__version__} imported")

print("\n[STEP 4] Testing torch...", flush=True)
try:
    import torch
    print(f"✓ torch {torch.__version__} imported")
except ImportError:
    print("✗ torch not available")

print("\n[STEP 5] Testing tensorflow (with env vars already set)...", flush=True)
import tensorflow as tf
print(f"✓ tensorflow {tf.__version__} imported")

print("\n[STEP 6] Testing tf.config.set_visible_devices...", flush=True)
tf.config.set_visible_devices([], 'GPU')
print("✓ GPU devices disabled")

print("\n[STEP 7] Now testing full common_imports import...", flush=True)
import intellicrack.utils.core.common_imports
print("✓ common_imports imported successfully!")

print("\n[COMPLETE] All imports successful!")
