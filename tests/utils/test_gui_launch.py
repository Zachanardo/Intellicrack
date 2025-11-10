#!/usr/bin/env python
"""Test GUI instantiation without showing window."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing GUI instantiation...")

try:
    print("1. Setting up environment...")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

    print("2. Importing PyQt6 components...")
    from intellicrack.handlers.pyqt6_handler import QApplication, HAS_PYQT
    print(f"OK PyQt6 available: {HAS_PYQT}")

    print("3. Creating QApplication...")
    app = QApplication(sys.argv)
    print("OK QApplication created successfully!")

    print("4. Importing IntellicrackApp...")
    from intellicrack.ui.main_app import IntellicrackApp
    print("OK IntellicrackApp imported successfully!")

    print("5. Creating IntellicrackApp instance...")
    window = IntellicrackApp()
    print("OK IntellicrackApp instantiated successfully!")

    print("6. Testing window properties...")
    print(f"Window title: {window.windowTitle()}")
    print(f"Window size: {window.size().width()}x{window.size().height()}")
    print("OK GUI is ready to be shown!")

    print("OK All GUI tests passed! Intellicrack GUI is working.")

except Exception as e:
    print(f"FAIL GUI test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
