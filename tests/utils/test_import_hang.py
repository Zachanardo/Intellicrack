#!/usr/bin/env python
"""Test to identify which import is causing the hang."""

import sys
import time

print("Starting import test...")

# Test basic imports
try:
    print("1. Testing logger import...")
    from intellicrack.logger import logger
    print("   SUCCESS: logger imported")
except Exception as e:
    print(f"   FAILED: {e}")

try:
    print("2. Testing handlers import...")
    from intellicrack.handlers.tensorflow_handler import tensorflow as tf
    print("   SUCCESS: tensorflow_handler imported")
except Exception as e:
    print(f"   FAILED: {e}")

try:
    print("3. Testing config import...")
    from intellicrack.config import CONFIG
    print("   SUCCESS: config imported")
except Exception as e:
    print(f"   FAILED: {e}")

try:
    print("4. Testing full intellicrack import...")
    import intellicrack
    print("   SUCCESS: intellicrack imported")
except Exception as e:
    print(f"   FAILED: {e}")

print("All imports completed!")
