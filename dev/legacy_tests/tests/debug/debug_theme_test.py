#!/usr/bin/env python3
"""Test theme application to find the specific crash."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_theme_application():
    """Test applying theme settings."""
    try:
        print("1. Importing Qt...")
        from PyQt6.QtWidgets import QApplication, QMainWindow
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QPalette, QColor
        print("   ✓ Qt imported")

        print("2. Creating QApplication...")
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        print("3. Creating QMainWindow...")
        window = QMainWindow()
        print("   ✓ QMainWindow created")

        print("4. Setting Fusion style...")
        app.setStyle("Fusion")
        print("   ✓ Fusion style set")

        print("5. Creating dark palette...")
        dark_palette = QPalette()
        print("   ✓ QPalette created")

        print("6. Setting palette colors...")
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        print("   ✓ Colors set")

        print("7. Applying palette...")
        app.setPalette(dark_palette)
        print("   ✓ Palette applied")

        print("8. Setting stylesheet...")
        app.setStyleSheet("""
            QWidget {
                background-color: #353535;
                color: white;
            }
        """)
        print("   ✓ Stylesheet applied")

        print("9. Showing window...")
        window.show()
        print("   ✓ Window shown")

        print("10. Processing events...")
        app.processEvents()
        print("   ✓ Events processed")

        print("11. Closing...")
        window.close()
        app.quit()
        print("   ✓ Closed")

        return 0

    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    print("Testing theme application...")
    result = test_theme_application()
    print(f"Test completed with exit code: {result}")
    sys.exit(result)
