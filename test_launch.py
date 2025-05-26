#!/usr/bin/env python3
"""Test the launch function directly"""

import sys
import os
import logging

# Set up path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set platform
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Suppress Ghidra warnings
logging.getLogger('intellicrack.config').setLevel(logging.ERROR)

try:
    from PyQt5.QtWidgets import QApplication
    print("PyQt5 imported OK")
    
    from intellicrack.ui.main_app import launch, IntellicrackApp
    print(f"launch imported: {launch}")
    print(f"IntellicrackApp imported: {IntellicrackApp}")
    
    # Create Qt app first
    app = QApplication(sys.argv)
    print("QApplication created")
    
    # Check IntellicrackApp before calling launch
    print(f"IntellicrackApp is: {IntellicrackApp}")
    print(f"IntellicrackApp type: {type(IntellicrackApp)}")
    
    # Try creating instance directly
    try:
        test_window = IntellicrackApp()
        print("IntellicrackApp instance created successfully")
    except Exception as e:
        print(f"Failed to create IntellicrackApp instance: {e}")
        import traceback
        traceback.print_exc()
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()