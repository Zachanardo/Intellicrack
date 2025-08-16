#!/usr/bin/env python
"""Test direct intellicrack import bypassing utils."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing direct intellicrack import...")

try:
    print("1. Setting up environment...")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

    print("2. Importing intellicrack directly...")
    import intellicrack

    print("✅ Intellicrack imported successfully!")
    print(f"Intellicrack version: {getattr(intellicrack, '__version__', 'unknown')}")

    print("✅ All tests passed!")

except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
