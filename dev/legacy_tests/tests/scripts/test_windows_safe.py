#!/usr/bin/env python3
"""Test Windows platform with safe settings."""

import os
import sys

# Force software rendering
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_ANGLE_PLATFORM'] = 'warp'  # Use WARP (Windows Advanced Rasterization Platform)
os.environ['QT_D3D_ADAPTER_INDEX'] = '1'  # Try different adapter

def main():
    """Test Windows platform."""
    try:
        print("Testing Windows platform with WARP...")

        from PyQt6.QtWidgets import QApplication, QMainWindow
        from intellicrack.ui.dialogs.common_imports import QTimer

        print("Creating QApplication...")
        app = QApplication(sys.argv)
        print("✓ QApplication created!")

        print("Creating window...")
        window = QMainWindow()
        window.setWindowTitle("Test")
        window.resize(400, 300)
        print("✓ Window created!")

        print("Showing window...")
        window.show()
        print("✓ Window shown!")

        # Auto-close after 2 seconds
        QTimer.singleShot(2000, app.quit)

        print("Starting event loop...")
        result = app.exec()
        print(f"✓ Event loop finished with code: {result}")

        return result

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
