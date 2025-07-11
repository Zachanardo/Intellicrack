#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Test script to debug import issues"""

import sys
import os

print("Python version:", sys.version)
print("Python executable:", sys.executable)
print("Current directory:", os.getcwd())
print("sys.path:")
for p in sys.path:
    print(f"  {p}")

print("\n--- Testing imports ---")

try:
    print("1. Importing intellicrack...")
    import intellicrack
    print("   SUCCESS: intellicrack imported")
except Exception as e:
    print(f"   FAILED: {e}")
    import traceback
    traceback.print_exc()

try:
    print("\n2. Importing intellicrack.main...")
    from intellicrack.main import main
    print("   SUCCESS: intellicrack.main imported")
except Exception as e:
    print(f"   FAILED: {e}")
    import traceback
    traceback.print_exc()

try:
    print("\n3. Importing intellicrack.ui.main_app...")
    from intellicrack.ui.main_app import launch
    print("   SUCCESS: intellicrack.ui.main_app.launch imported")
except Exception as e:
    print(f"   FAILED: {e}")
    import traceback
    traceback.print_exc()

try:
    print("\n4. Testing PyQt5...")
    from PyQt6.QtWidgets import QApplication
    print("   SUCCESS: PyQt5 imported")
    
    print("\n5. Creating QApplication...")
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    print("   SUCCESS: QApplication created")
    
except Exception as e:
    print(f"   FAILED: {e}")
    import traceback
    traceback.print_exc()

print("\n--- Import test complete ---")