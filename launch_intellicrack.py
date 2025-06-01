#!/usr/bin/env python3
"""
Launch Intellicrack with all fixes applied
"""

import sys
import os
import warnings

# Add current directory to path for our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix 1: Install proper siphash implementation before pytools tries to import it
try:
    import siphash24
except ImportError:
    # Use our replacement implementation
    import siphash24_replacement
    sys.modules['siphash24'] = siphash24_replacement

# Fix 2: Suppress remaining warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pytools.persistent_dict")

# Fix 3: Fix Qt properly - create font directory if needed
qt_base = os.path.join(sys.prefix, "Lib", "site-packages", "PyQt5", "Qt5")
if os.path.exists(qt_base):
    fonts_dir = os.path.join(qt_base, "lib", "fonts")
    try:
        os.makedirs(fonts_dir, exist_ok=True)
    except:
        pass

# Fix 4: Set Qt environment variables
os.environ['QT_QPA_FONTDIR'] = ''  # Use system fonts
os.environ['QT_LOGGING_RULES'] = 'qt.qpa.fonts=false'  # Specifically disable font warnings

# Fix 5: Install custom Qt message handler
def qt_message_handler(mode, context, message):
    # Filter out specific annoying messages
    if "QFontDatabase" in message:
        return
    if "setLayout" in message and "which already has a layout" in message:
        return
    if "propagateSizeHints" in message:
        return
    # Let other messages through
    if mode > 1:  # Warning or higher
        print(f"Qt: {message}")

try:
    from PyQt5 import QtCore
    QtCore.qInstallMessageHandler(qt_message_handler)
except:
    pass

# Now import and run Intellicrack
def main():
    try:
        print("Launching Intellicrack...")
        
        # Add the project directory to Python path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Create QApplication instance BEFORE importing main_app to avoid duplicate instances
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QFontDatabase
        from PyQt5.QtCore import Qt
        
        # Check if QApplication already exists
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            
        # Set application attributes to reduce warnings
        app.setAttribute(Qt.AA_DisableWindowContextHelpButton)
        
        # Force Qt to use system fonts (prevents font directory warnings)
        QFontDatabase.addApplicationFont("")  # Empty string uses system fonts
        
        # Import and run the application
        from intellicrack.ui.main_app import launch
        return launch()
        
    except ImportError as e:
        print(f"\nERROR: Failed to import Intellicrack modules")
        print(f"Import error: {e}")
        print("\nMake sure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        return 1
        
    except Exception as e:
        print(f"\nERROR: Failed to launch Intellicrack")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        
        print("\nTroubleshooting:")
        print("1. Check if PyQt5 is properly installed:")
        print("   pip install PyQt5==5.15.9")
        print("2. Run dependency fixer:")
        print("   python fix_launch_issues.py")
        print("3. Check error messages above for specific issues")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())