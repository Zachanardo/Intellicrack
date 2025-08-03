#!/usr/bin/env python
"""Test common_imports module specifically"""

import os
import sys

# Configure TensorFlow first
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

print("[TEST] Testing intellicrack.utils.core.common_imports import...")
print("[TEST] Adding timeout alarm...")

import signal

def timeout_handler(signum, frame):
    print("\n[TEST] TIMEOUT! Import took longer than 10 seconds")
    print("[TEST] The import is hanging somewhere")
    sys.exit(1)

# Set a 10-second timeout
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(10)

try:
    print("[TEST] Starting import...", flush=True)
    import intellicrack.utils.core.common_imports
    print("[TEST] Successfully imported common_imports!")
    signal.alarm(0)  # Cancel the alarm
except Exception as e:
    print(f"[TEST] Import failed with error: {e}")
    import traceback
    traceback.print_exc()
    signal.alarm(0)
    sys.exit(1)

print("[TEST] Import test complete!")
