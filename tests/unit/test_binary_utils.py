#!/usr/bin/env python
"""Test importing binary_utils directly."""

import sys
import os

# Add project root to path
from intellicrack.utils.path_resolver import get_project_root

sys.path.insert(0, str(get_project_root()))

print("Testing binary_utils import...")

try:
    print("\n1. Importing intellicrack.utils.binary.binary_utils directly...")
    from intellicrack.utils.binary import binary_utils
    print("   ✓ binary_utils imported")

    print("\n✅ Import successful!")

except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
