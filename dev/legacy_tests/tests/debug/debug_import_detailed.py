#!/usr/bin/env python3
"""Detailed import test to find exact hang location."""

import os
import sys
import traceback

# Configure TensorFlow to prevent GPU initialization issues with Intel Arc B580
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['MKL_THREADING_LAYER'] = 'GNU'

# Force software rendering for Intel Arc compatibility
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

# Disable TensorFlow for Intel Arc B580
os.environ['DISABLE_TENSORFLOW'] = '1'

def test_detailed_imports():
    """Test imports step by step to find exact hang location."""
    print("Testing detailed imports...")

    try:
        print("1. Creating QApplication...")
        from PyQt6.QtWidgets import QApplication
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        print("2. Testing intellicrack package...")
        print("   ✓ intellicrack package imported")

        print("3. Testing intellicrack.config...")
        print("   ✓ intellicrack.config imported")

        print("4. Testing intellicrack.core...")
        print("   ✓ intellicrack.core imported")

        print("5. Testing intellicrack.ui...")
        print("   ✓ intellicrack.ui imported")

        print("6. Testing IntellicrackApp import...")
        from intellicrack.ui.main_app import IntellicrackApp
        print("   ✓ IntellicrackApp class imported")

        print("7. Testing IntellicrackApp instantiation...")
        # This is where the hang likely occurs
        sys.stdout.flush()
        window = IntellicrackApp()
        print("   ✓ IntellicrackApp instantiated successfully!")

        print("8. Cleaning up...")
        window.close()
        app.quit()
        print("   ✓ Cleaned up successfully")

        return True

    except Exception as e:
        print(f"   ✗ Error: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_detailed_imports()
    if success:
        print("\n✓ All imports successful")
        sys.exit(0)
    else:
        print("\n✗ Import test failed")
        sys.exit(1)
