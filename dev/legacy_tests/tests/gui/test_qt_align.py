#!/usr/bin/env python3
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

print("Testing Qt alignment fix...")

try:
    from intellicrack.ui.main_app import launch
    print("Import successful")
    result = launch()
    print(f"Launch returned: {result}")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
