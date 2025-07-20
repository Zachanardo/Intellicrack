#!/usr/bin/env python3
"""Test the simplest possible GUI launch."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'desktop'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def main():
    """Test simple GUI."""
    try:
        print("Creating simple GUI test...")
        
        from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton
        from PyQt6.QtCore import QTimer
        
        app = QApplication(sys.argv)
        
        window = QMainWindow()
        window.setWindowTitle("Intellicrack Working!")
        window.setGeometry(100, 100, 800, 600)
        
        # Central widget
        central = QWidget()
        layout = QVBoxLayout(central)
        
        # Add label
        label = QLabel("<h1>Intellicrack is Running!</h1>")
        layout.addWidget(label)
        
        # Add button
        button = QPushButton("Click to Exit")
        button.clicked.connect(app.quit)
        layout.addWidget(button)
        
        window.setCentralWidget(central)
        
        # Show window
        window.show()
        
        print("✓ Window created and shown successfully!")
        print("Application is now running. Click the button or close the window to exit.")
        
        return app.exec()
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())