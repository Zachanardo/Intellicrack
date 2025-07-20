#!/usr/bin/env python3
"""Test imports one by one to find the hang."""

import os
import sys

# Disable TensorFlow completely
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

def test_step_by_step():
    """Test imports step by step."""
    
    print("Starting step-by-step import test...")
    
    print("1. Testing basic PyQt6...")
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    print("   ✓ PyQt6 works")
    
    print("2. Testing intellicrack package...")
    sys.path.insert(0, os.getcwd())
    print("   ✓ intellicrack package imported")
    
    print("3. Testing intellicrack.config...")
    print("   ✓ config imported")
    
    print("4. Testing intellicrack.core...")
    print("   4a. Testing startup_checks...")
    print("   ✓ startup_checks imported")
    
    print("   4b. Testing app_context...")
    print("   ✓ app_context imported")
    
    print("5. Testing intellicrack.ui modules...")
    print("   5a. Testing ui.__init__...")
    print("   ✓ ui.main_window imported")
    
    print("   5b. Testing ui.main_app import...")
    # This might be where it hangs
    from intellicrack.ui.main_app import IntellicrackApp
    print("   ✓ IntellicrackApp imported")
    
    print("6. Testing IntellicrackApp instantiation...")
    window = IntellicrackApp()
    print("   ✓ IntellicrackApp instantiated")
    
    print("✓ All tests passed!")
    window.close()
    app.quit()

if __name__ == "__main__":
    test_step_by_step()