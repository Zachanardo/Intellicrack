#!/usr/bin/env python3
"""Test script to capture specific launch errors"""

import sys
import traceback

try:
    print("Attempting to launch Intellicrack...")
    sys.path.insert(0, '/mnt/c/Intellicrack')
    
    # Try importing the main module
    from launch_intellicrack import main
    
    # Try running main
    main()
    
except Exception as e:
    print(f"\nERROR TYPE: {type(e).__name__}")
    print(f"ERROR MESSAGE: {e}")
    print("\nFULL TRACEBACK:")
    traceback.print_exc()