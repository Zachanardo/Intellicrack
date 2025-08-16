#!/usr/bin/env python
"""Test importing utils.logger directly."""

import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")

print("Testing utils.logger import...")

try:
    print("\n1. Importing intellicrack.utils.logger directly...")
    from intellicrack.utils import logger
    print("   ✓ utils.logger imported")

    print("\n✅ Import successful!")

except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
