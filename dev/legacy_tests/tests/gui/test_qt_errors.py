#!/usr/bin/env python3
"""Test for Qt-specific errors"""

import sys
sys.path.insert(0, '/mnt/c/Intellicrack')

try:
    from intellicrack.ui.dialogs.common_imports import QApplication
    app = QApplication(sys.argv)

    # Test imports that might fail
    print("Testing main_app import...")
    from intellicrack.ui.main_app import IntellicrackMainWindow

    print("Creating main window...")
    window = IntellicrackMainWindow()

    print("Success! Window created.")

except AttributeError as e:
    print(f"\nAttributeError: {e}")
    print(f"Object: {e.obj if hasattr(e, 'obj') else 'Unknown'}")
    print(f"Name: {e.name if hasattr(e, 'name') else 'Unknown'}")
    import traceback
    traceback.print_exc()

except Exception as e:
    print(f"\nError: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
