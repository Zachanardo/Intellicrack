#!/usr/bin/env python3
"""Minimal launch test to identify where the hang occurs."""

import os
import sys

# Configure TensorFlow to prevent GPU initialization issues with Intel Arc B580
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['MKL_THREADING_LAYER'] = 'GNU'

# Force software rendering for Intel Arc compatibility
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_minimal_qt():
    """Test basic Qt functionality."""
    print("1. Testing basic Qt imports...")
    try:
        from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
        print("   ✓ Qt imports successful")
    except Exception as e:
        print(f"   ✗ Qt import failed: {e}")
        return False

    print("2. Creating QApplication...")
    try:
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")
    except Exception as e:
        print(f"   ✗ QApplication creation failed: {e}")
        return False

    print("3. Creating simple QMainWindow...")
    try:
        window = QMainWindow()
        window.setWindowTitle("Test Window")
        window.setGeometry(100, 100, 400, 300)
        print("   ✓ QMainWindow created")
    except Exception as e:
        print(f"   ✗ QMainWindow creation failed: {e}")
        return False

    print("4. Adding simple widget...")
    try:
        label = QLabel("Test Label")
        window.setCentralWidget(label)
        print("   ✓ Widget added")
    except Exception as e:
        print(f"   ✗ Widget addition failed: {e}")
        return False

    print("5. Showing window briefly...")
    try:
        window.show()
        app.processEvents()  # Process any pending events
        print("   ✓ Window shown")
    except Exception as e:
        print(f"   ✗ Window show failed: {e}")
        return False

    print("6. Closing application...")
    try:
        window.close()
        app.quit()
        print("   ✓ Application closed cleanly")
        return True
    except Exception as e:
        print(f"   ✗ Application close failed: {e}")
        return False

if __name__ == "__main__":
    print("Starting minimal Qt test...")
    success = test_minimal_qt()
    if success:
        print("\n✓ Minimal Qt test passed - Qt is working")
        sys.exit(0)
    else:
        print("\n✗ Minimal Qt test failed")
        sys.exit(1)
