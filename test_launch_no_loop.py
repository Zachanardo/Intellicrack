#!/usr/bin/env python3
"""Test launching Intellicrack without event loop."""

import os
import sys

# Set Qt to offscreen mode for WSL
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from PyQt5.QtWidgets import QApplication
    from intellicrack.ui.main_app import IntellicrackApp
    
    print("Creating QApplication...")
    app = QApplication(sys.argv)
    
    print("Creating IntellicrackApp...")
    window = IntellicrackApp()
    
    print("SUCCESS! IntellicrackApp created successfully!")
    print(f"Window title: {window.windowTitle()}")
    print(f"Window size: {window.size()}")
    
    # Don't start the event loop, just exit
    print("Test complete - GUI initialized successfully!")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()