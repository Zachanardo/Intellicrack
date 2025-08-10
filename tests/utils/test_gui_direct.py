#!/usr/bin/env python
"""Direct GUI launch test to bypass startup checks."""

import os
import sys

# Disable TensorFlow GPU and warnings
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["MKL_THREADING_LAYER"] = "GNU"

# Add Intellicrack to path
sys.path.insert(0, r"C:\Intellicrack")

print("Test 1: Importing main_app module...")
try:
    from intellicrack.ui.main_app import launch
    print("✓ main_app imported successfully")
except ImportError as e:
    print(f"✗ Failed to import main_app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\nTest 2: Attempting to launch GUI...")
try:
    result = launch()
    print(f"Launch returned: {result}")
except Exception as e:
    print(f"✗ Launch failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)