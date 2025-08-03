#!/usr/bin/env python
"""Minimal test to check application launch"""

import sys
import os

# Configure TensorFlow to prevent GPU initialization issues
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

print("[TEST] Starting minimal launch test...")

try:
    print("[TEST] Importing PyQt6...")
    from PyQt6.QtWidgets import QApplication
    print("[TEST] PyQt6 imported successfully")

    print("[TEST] Creating QApplication...")
    app = QApplication(sys.argv)
    print("[TEST] QApplication created successfully")

    print("[TEST] Importing IntellicrackApp...")
    from intellicrack.ui.main_app import IntellicrackApp
    print("[TEST] IntellicrackApp imported successfully")

    print("[TEST] Creating IntellicrackApp...")
    window = IntellicrackApp()
    print("[TEST] IntellicrackApp created successfully")

    print("[TEST] Setting up window...")
    window.setWindowTitle("Intellicrack Test")
    window.resize(1200, 800)
    window.show()
    print("[TEST] Window shown successfully")

    print("[TEST] Application launched successfully!")
    sys.exit(0)  # Exit without running event loop to avoid hanging

except Exception as e:
    print(f"[TEST] ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
