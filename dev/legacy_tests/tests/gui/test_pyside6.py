#!/usr/bin/env python3
"""Test PySide6 as an alternative to PyQt6."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def main():
    """Test PySide6."""
    try:
        print("Testing PySide6...")

        from PySide6.QtWidgets import QApplication, QMainWindow, QLabel
        from PySide6.QtCore import Qt

        app = QApplication(sys.argv)

        window = QMainWindow()
        window.setWindowTitle("PySide6 Test")
        window.setGeometry(100, 100, 400, 300)

        label = QLabel("PySide6 is working!")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        window.setCentralWidget(label)

        window.show()

        print("✓ PySide6 window created successfully!")
        return app.exec()

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
