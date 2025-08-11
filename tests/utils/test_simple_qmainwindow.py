#!/usr/bin/env python
"""Simple test of QMainWindow from pyqt6_handler"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Testing QMainWindow directly from pyqt6_handler...")

try:
    from intellicrack.handlers.pyqt6_handler import QMainWindow, QApplication, HAS_PYQT
    print(f"✅ Successfully imported QMainWindow")
    print(f"   HAS_PYQT: {HAS_PYQT}")
    print(f"   QMainWindow type: {type(QMainWindow)}")
    print(f"   QMainWindow module: {QMainWindow.__module__ if hasattr(QMainWindow, '__module__') else 'N/A'}")
    
    # Check for key methods
    methods_to_check = ['setGeometry', 'setWindowTitle', 'isVisible', 'windowState', 'parent']
    for method in methods_to_check:
        has_method = hasattr(QMainWindow, method)
        print(f"   Has {method}: {has_method}")
    
    if HAS_PYQT:
        print("\n✅ Creating QApplication...")
        app = QApplication(sys.argv)
        
        print("✅ Creating QMainWindow instance...")
        window = QMainWindow()
        print(f"   Window type: {type(window)}")
        
        # Test methods
        try:
            print("✅ Testing setGeometry...")
            window.setGeometry(100, 100, 800, 600)
            print("   setGeometry worked!")
            
            print("✅ Testing setWindowTitle...")
            window.setWindowTitle("Test")
            print("   setWindowTitle worked!")
            
            print("✅ All QMainWindow methods working!")
            
        except Exception as e:
            print(f"❌ Method test failed: {e}")
    else:
        print("❌ HAS_PYQT is False")
        
except Exception as e:
    print(f"❌ Import failed: {e}")
    import traceback
    traceback.print_exc()