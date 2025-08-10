#!/usr/bin/env python
"""Test if TensorFlow import is causing the hang."""

import os
import sys

# Set environment variables before any imports
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["MKL_THREADING_LAYER"] = "GNU"

print("Starting TensorFlow import test...")
print("Environment variables set:")
print(f"  TF_CPP_MIN_LOG_LEVEL={os.environ.get('TF_CPP_MIN_LOG_LEVEL')}")
print(f"  CUDA_VISIBLE_DEVICES={os.environ.get('CUDA_VISIBLE_DEVICES')}")
print(f"  MKL_THREADING_LAYER={os.environ.get('MKL_THREADING_LAYER')}")

sys.stdout.flush()

print("\nAttempting to import tensorflow...")
sys.stdout.flush()

try:
    import tensorflow as tf
    print(f"✓ TensorFlow {tf.__version__} imported successfully")
    
    # Try to disable GPU
    print("Disabling GPU devices...")
    tf.config.set_visible_devices([], 'GPU')
    print("✓ GPU disabled")
    
    # Test basic operation
    print("Testing basic tensor operation...")
    test_tensor = tf.constant([1, 2, 3])
    print(f"✓ Created tensor: {test_tensor}")
    
except ImportError as e:
    print(f"✗ TensorFlow not available: {e}")
except Exception as e:
    print(f"✗ Error during TensorFlow operations: {e}")
    import traceback
    traceback.print_exc()

print("\nTest complete!")
sys.stdout.flush()