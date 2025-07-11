#!/usr/bin/env python3
import os
import sys

# Set environment variables
os.environ['QT_LOGGING_RULES'] = '*=false'
os.environ['QT_FORCE_STDERR_LOGGING'] = '1'

print("Direct test starting...")

try:
    # Import and run directly
    from intellicrack.__main__ import main
    print("Main imported successfully")
    main()
except Exception as e:
    print(f"ERROR in main: {e}")
    import traceback
    traceback.print_exc()