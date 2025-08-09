#!/usr/bin/env python3
"""Test importing IntellicrackApp class to isolate import issues."""

import os
import sys
import traceback

# Configure TensorFlow to prevent GPU initialization issues with Intel Arc B580
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['MKL_THREADING_LAYER'] = 'GNU'

# Force software rendering for Intel Arc compatibility
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_class_import():
    """Test importing IntellicrackApp class without instantiating."""
    print("Testing IntellicrackApp class import...")

    try:
        print("1. Importing PyQt6...")
        from intellicrack.ui.dialogs.common_imports import QApplication
        print("   ✓ PyQt6 imported")

        print("2. Creating QApplication...")
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        print("3. Importing IntellicrackApp class...")
        from intellicrack.ui.main_app import IntellicrackApp
        print("   ✓ IntellicrackApp class imported successfully")

        print("4. Checking class type...")
        print(f"   Class type: {type(IntellicrackApp)}")
        print(f"   Class name: {IntellicrackApp.__name__}")
        print(f"   Base classes: {IntellicrackApp.__bases__}")
        print("   ✓ Class information retrieved")

        print("5. Testing class instantiation (this is where it likely hangs)...")
        # This is likely where the hang occurs
        window = IntellicrackApp()
        print("   ✓ IntellicrackApp instantiated successfully!")

        print("6. Closing...")
        window.close()
        app.quit()
        print("   ✓ Closed cleanly")

        return True

    except Exception as e:
        print(f"   ✗ Error: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_class_import()
    if success:
        print("\n✓ IntellicrackApp test passed")
        sys.exit(0)
    else:
        print("\n✗ IntellicrackApp test failed")
        sys.exit(1)
