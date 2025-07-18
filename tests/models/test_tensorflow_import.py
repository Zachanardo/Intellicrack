#!/usr/bin/env python
"""Test TensorFlow import isolation"""

import os
import sys

print("[TF TEST] Setting environment variables...")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

print("[TF TEST] Importing TensorFlow...")
try:
    import tensorflow as tf
    print(f"[TF TEST] TensorFlow {tf.__version__} imported successfully")
except Exception as e:
    print(f"[TF TEST] Failed to import TensorFlow: {e}")
    sys.exit(1)

print("[TF TEST] Setting visible devices...")
try:
    tf.config.set_visible_devices([], 'GPU')
    print("[TF TEST] GPU devices disabled successfully")
except Exception as e:
    print(f"[TF TEST] Failed to set visible devices: {e}")

print("[TF TEST] Listing physical devices...")
try:
    devices = tf.config.list_physical_devices()
    print(f"[TF TEST] Found {len(devices)} devices:")
    for device in devices:
        print(f"  - {device}")
except Exception as e:
    print(f"[TF TEST] Failed to list devices: {e}")

print("[TF TEST] Complete!")