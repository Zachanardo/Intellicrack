#!/usr/bin/env python3
"""Test launching the app with desktop OpenGL."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'desktop'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def main():
    """Launch Intellicrack."""
    try:
        print("Testing Intellicrack launch...")

        # Import the main module
        from intellicrack.main import intellicrack_main

        # Call main
        result = intellicrack_main()
        print(f"App returned: {result}")
        return result

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
