#!/usr/bin/env python3
"""Minimal launch script to bypass problematic components."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

# Disable problematic imports
os.environ['SKIP_MONITORING_WIDGETS'] = '1'

def main():
    """Launch minimal Intellicrack."""
    try:
        print("Starting minimal Intellicrack...")

        from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QTabWidget
        from PyQt6.QtCore import Qt

        app = QApplication(sys.argv)

        # Create main window
        window = QMainWindow()
        window.setWindowTitle("Intellicrack - Minimal Mode")
        window.setGeometry(100, 100, 1200, 800)

        # Create tab widget
        tabs = QTabWidget()

        # Add placeholder tabs
        for i, name in enumerate(["Dashboard", "Analysis", "Tools", "Exploitation", "AI Assistant", "Project", "Settings"]):
            label = QLabel(f"{name} Tab - Content will be loaded here")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            tabs.addTab(label, name)

        window.setCentralWidget(tabs)

        # Show window
        window.show()

        print("✓ Application launched successfully!")
        return app.exec()

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
