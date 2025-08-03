#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    exec(open("test_centralized_logging_complete.py").read())
except Exception as e:
    with open("test_error.txt", "w") as f:
        f.write(f"Test execution error: {e}\n")
        import traceback
        f.write(traceback.format_exc())
    print(f"Error running tests: {e}")