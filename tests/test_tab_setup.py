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

"""
Test script to identify which tab setup method is causing the GUI hang
"""
import sys
import os
import logging
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def test_minimal_app():
    """Test creating a minimal QMainWindow"""
    print("[TEST] Creating QApplication...")
    app = QApplication(sys.argv)
    
    print("[TEST] Creating QMainWindow...")
    window = QMainWindow()
    window.setWindowTitle("Minimal Test Window")
    window.setGeometry(100, 100, 800, 600)
    
    # Create simple central widget
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    
    layout = QVBoxLayout(central_widget)
    label = QLabel("Minimal test window - if you see this, basic Qt works")
    layout.addWidget(label)
    
    print("[TEST] Showing window...")
    window.show()
    
    print("[TEST] Window should be visible now")
    print(f"[TEST] Window visible: {window.isVisible()}")
    print(f"[TEST] Window geometry: {window.geometry()}")
    
    # Don't start event loop, just test creation
    app.processEvents()
    
    print("[TEST] Test completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(test_minimal_app())