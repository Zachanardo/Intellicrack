#!/usr/bin/env python3
"""Test with all acceleration disabled."""

import os
import sys

# Completely disable all acceleration
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'offscreen'  # Try offscreen platform
os.environ['QT_LOGGING_RULES'] = 'qt.qpa.gl=true'

def main():
    """Test offscreen mode."""
    try:
        print("Testing with offscreen platform...")
        
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import QCoreApplication
        
        # Try headless mode
        QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_UseSoftwareOpenGL)
        
        print("Creating QApplication...")
        app = QApplication(sys.argv + ['-platform', 'offscreen'])
        print("✓ QApplication created in offscreen mode!")
        
        app.quit()
        return 0
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())