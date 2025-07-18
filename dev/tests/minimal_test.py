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

"""Minimal test - just create and show a window"""

import sys
import os

# Force software rendering
os.environ['QT_OPENGL'] = 'software'

print("Creating minimal Qt window...")

try:
    from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
    from PyQt6.QtCore import Qt

    print("Qt imported successfully")

    # Create app
    app = QApplication(sys.argv)
    print("QApplication created")

    # Create window
    window = QMainWindow()
    window.setWindowTitle("Intellicrack Minimal Test")
    window.resize(600, 400)

    # Add content
    label = QLabel("If you see this window, Qt is working correctly!")
    label.setAlignment(Qt.AlignCenter)
    window.setCentralWidget(label)

    print("Window created")

    # Show window
    window.show()
    print("Window shown")

    # Run event loop
    print("Starting event loop...")
    sys.exit(app.exec())

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    input("Press Enter to exit...")
