#!/usr/bin/env python3
import sys
import traceback

try:
    from intellicrack.ui.main_app import launch
    result = launch()
    print(f"Launch returned: {result}")
except Exception as e:
    print(f"ERROR: {e}")
    traceback.print_exc()
    sys.exit(1)
