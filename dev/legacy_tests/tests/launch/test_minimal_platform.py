#!/usr/bin/env python3
"""Test with minimal platform."""

import os
import sys

def main():
    """Test minimal platform."""
    try:
        print("Testing with minimal platform...")
        
        from PyQt6.QtWidgets import QApplication
        
        print("Creating QApplication with minimal platform...")
        app = QApplication(sys.argv + ['-platform', 'minimal'])
        print("✓ QApplication created with minimal platform!")
        
        # The app won't show any windows but should at least create
        app.quit()
        return 0
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())