#!/usr/bin/env python3
"""Test script to capture launch errors"""

import sys
import traceback

try:
    print("Starting Intellicrack launch test...")
    sys.path.insert(0, '/mnt/c/Intellicrack')
    
    from launch_intellicrack import main
    main()
    
except Exception as e:
    print(f"\nERROR: {type(e).__name__}: {e}")
    print("\nFull traceback:")
    traceback.print_exc()