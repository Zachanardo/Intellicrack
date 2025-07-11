#!/usr/bin/env python3
import os
os.environ['QT_DEBUG_PLUGINS'] = '1'

print("Starting quick test...")

try:
    print("Importing PyQt6...")
    from PyQt6.QtWidgets import QApplication
    print("PyQt6 imported successfully")
    
    print("Importing intellicrack modules...")
    from intellicrack.ui.main_app import IntellicrackApp
    print("IntellicrackApp imported successfully")
    
except Exception as e:
    print(f"Import ERROR: {e}")
    import traceback
    traceback.print_exc()

print("Test complete")