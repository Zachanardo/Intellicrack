#!/usr/bin/env python3
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

print("Testing imports step by step...")

try:
    print("1. Importing PyQt6...")
    from PyQt6.QtWidgets import QApplication, QMainWindow
    print("   SUCCESS")

    print("2. Importing common_imports...")
    from intellicrack.ui.common_imports import *
    print("   SUCCESS")

    print("3. Importing main_app...")
    from intellicrack.ui import main_app
    print("   SUCCESS")

    print("4. Importing IntellicrackApp class...")
    from intellicrack.ui.main_app import IntellicrackApp
    print("   SUCCESS")

    print("5. Importing launch function...")
    from intellicrack.ui.main_app import launch
    print("   SUCCESS")

except Exception as e:
    print(f"   FAILED: {e}")
    import traceback
    traceback.print_exc()

print("\nAll imports completed!")
