#!/usr/bin/env python
"""Test UI import after fixing pyqt6_handler circular import."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing UI import after fixing pyqt6_handler circular import...")

try:
    print("1. Setting up environment...")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

    print("2. Testing intellicrack base import...")
    import intellicrack
    print("OK Intellicrack base import successful!")

    print("3. Testing direct UI import...")
    try:
        from intellicrack import ui
        if ui is not None:
            print("OK UI import successful!")
        else:
            print("WARNING UI import returned None - checking details...")

        print("4. Testing direct pyqt6_handler import...")
        from intellicrack.handlers.pyqt6_handler import HAS_PYQT, PYQT6_AVAILABLE
        print(f"OK PyQt6 handler import successful! HAS_PYQT={HAS_PYQT}, PYQT6_AVAILABLE={PYQT6_AVAILABLE}")

        print("5. Testing main_app import...")
        try:
            from intellicrack.ui.main_app import IntellicrackApp
            print("OK IntellicrackApp import successful!")
        except ImportError as e:
            print(f"FAIL IntellicrackApp import failed: {e}")

    except ImportError as e:
        print(f"FAIL UI import failed: {e}")
        import traceback
        traceback.print_exc()

    print("OK All tests completed!")

except Exception as e:
    print(f"FAIL Test failed with error: {e}")
    import traceback
    traceback.print_exc()
