#!/usr/bin/env python3
"""Debug script to find the exact import error."""

import sys
import traceback

# Add current directory to path
sys.path.insert(0, '.')

try:
    import intellicrack.main
    print("Successfully imported intellicrack.main")
except Exception as e:
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {str(e)}")
    print("\nFull traceback:")
    traceback.print_exc()