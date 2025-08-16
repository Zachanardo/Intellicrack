#!/usr/bin/env python
"""Test which QMainWindow is being used in main_app.py"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing QMainWindow import from main_app...")

try:
    print("1. Testing pyqt6_handler directly...")
    from intellicrack.handlers.pyqt6_handler import QMainWindow, HAS_PYQT
    print(f"   QMainWindow from handler: {QMainWindow}")
    print(f"   Has PyQt6: {HAS_PYQT}")
    print(f"   QMainWindow module: {QMainWindow.__module__}")
    print(f"   QMainWindow methods: {[m for m in dir(QMainWindow) if 'setGeometry' in m]}")

    print("\n2. Testing import from main_app.py...")
    # Import the specific section that imports QMainWindow
    import importlib.util
    spec = importlib.util.spec_from_file_location("main_app", "C:/Intellicrack/intellicrack/ui/main_app.py")
    main_app_module = importlib.util.module_from_spec(spec)

    # Execute just the imports
    print("   Executing main_app imports...")
    try:
        spec.loader.exec_module(main_app_module)

        # Check which QMainWindow is being used
        qmw = getattr(main_app_module, 'QMainWindow', None)
        if qmw:
            print(f"   QMainWindow from main_app: {qmw}")
            print(f"   QMainWindow module: {qmw.__module__}")
            print(f"   Has setGeometry: {hasattr(qmw, 'setGeometry')}")
            if hasattr(qmw, 'setGeometry'):
                print("   ✅ setGeometry method found")
            else:
                print("   ❌ setGeometry method NOT found")
        else:
            print("   ❌ QMainWindow not found in main_app module")

    except Exception as e:
        print(f"   ❌ Error executing main_app: {e}")
        import traceback
        traceback.print_exc()

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
