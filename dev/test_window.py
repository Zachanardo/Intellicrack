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

"""Test script to verify Qt window display"""

import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt

def main():
    print("Creating Qt application...")
    app = QApplication(sys.argv)
    
    print(f"Platform: {sys.platform}")
    print(f"QT_QPA_PLATFORM: {os.environ.get('QT_QPA_PLATFORM', 'not set')}")
    
    # Create a simple window
    window = QMainWindow()
    window.setWindowTitle("Test Qt Window")
    window.resize(400, 300)
    
    # Add some content
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    
    layout = QVBoxLayout(central_widget)
    
    label = QLabel("This is a test Qt window")
    label.setAlignment(Qt.AlignCenter)
    layout.addWidget(label)
    
    button = QPushButton("Click me!")
    button.clicked.connect(lambda: print("Button clicked!"))
    layout.addWidget(button)
    
    # Show the window
    print("Showing window...")
    window.show()
    
    print(f"Window visible: {window.isVisible()}")
    print(f"Window geometry: {window.geometry()}")
    
    # Run the event loop
    print("Starting event loop...")
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())