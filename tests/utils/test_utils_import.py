#!/usr/bin/env python
"""Test utils import after disabling tool_wrappers."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing utils import after disabling tool_wrappers...")

try:
    print("1. Setting up environment...")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
    
    print("2. Importing utils...")
    import intellicrack.utils
    
    print("✅ Utils imported successfully!")
    print(f"Utils version: {intellicrack.utils.__version__}")
    
    # Test basic functionality
    print("3. Testing basic utils functions...")
    print(f"Logger available: {hasattr(intellicrack.utils, 'logger')}")
    print(f"Get logger available: {hasattr(intellicrack.utils, 'get_logger')}")
    
    print("✅ All tests passed!")
    
except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)