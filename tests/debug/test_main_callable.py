#!/usr/bin/env python3
"""Debug script to check if main() is callable."""

import sys
import traceback

# Add current directory to path
sys.path.insert(0, '.')

try:
    import intellicrack.main
    print("Successfully imported intellicrack.main")
    
    # Check if main exists and is callable
    if hasattr(intellicrack.main, 'main'):
        main_func = getattr(intellicrack.main, 'main')
        print(f"main exists: {main_func}")
        print(f"main type: {type(main_func)}")
        print(f"main is callable: {callable(main_func)}")
        
        if main_func is None:
            print("ERROR: main is None!")
        elif not callable(main_func):
            print("ERROR: main is not callable!")
        else:
            print("Attempting to call main()...")
            result = main_func()
            print(f"main() returned: {result}")
    else:
        print("ERROR: intellicrack.main does not have a 'main' attribute!")
        print(f"Available attributes: {dir(intellicrack.main)}")
        
except Exception as e:
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {str(e)}")
    print("\nFull traceback:")
    traceback.print_exc()