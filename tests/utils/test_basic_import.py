#!/usr/bin/env python
"""Test most basic imports."""

import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")

print("Starting basic import test...")

try:
    print("\n1. Testing logger import...")
    from intellicrack.logger import logger
    print("   ✓ Logger imported")
    
    print("\n✅ Logger import successful!")
    
except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)