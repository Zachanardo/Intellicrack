#!/usr/bin/env python3
"""Minimal test to see if Qt window can be created and shown."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_minimal_window():
    """Test creating and showing a minimal Qt window."""
    try:
        print("1. Importing Qt...")
        from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
        from intellicrack.ui.dialogs.common_imports import QTimer
        print("   ✓ Qt imported")

        print("2. Creating QApplication...")
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        print("3. Creating QMainWindow...")
        window = QMainWindow()
        window.setWindowTitle("Intellicrack Test")
        window.setGeometry(100, 100, 400, 300)
        print("   ✓ QMainWindow created")

        print("4. Adding content...")
        label = QLabel("Test window - if you see this, Qt is working!")
        window.setCentralWidget(label)
        print("   ✓ Content added")

        print("5. Showing window...")
        window.show()
        print("   ✓ Window shown")

        print("6. Processing events...")
        app.processEvents()
        print("   ✓ Events processed")

        print("7. Setting up auto-close timer...")
        timer = QTimer()
        timer.timeout.connect(app.quit)
        timer.start(3000)  # Close after 3 seconds
        print("   ✓ Timer set")

        print("8. Starting event loop...")
        result = app.exec()
        print(f"   ✓ Event loop finished with result: {result}")

        return result

    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    print("Testing minimal Qt window...")
    result = test_minimal_window()
    print(f"Test completed with exit code: {result}")
    sys.exit(result)
