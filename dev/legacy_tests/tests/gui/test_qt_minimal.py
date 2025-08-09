#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Minimal test to reproduce Qt startup issue.
"""

import sys

# Add the project root to the path
sys.path.insert(0, '/mnt/c/Intellicrack')

def test_qt_basic():
    """Test basic Qt functionality."""
    print("Testing basic Qt imports...")

    try:
        from PyQt6.QtWidgets import QApplication, QMainWindow
        print("✓ Basic PyQt5 imports successful")

        app = QApplication(sys.argv)
        window = QMainWindow()

        # Validate Qt application and window
        if app and hasattr(app, 'exec_') and window and hasattr(window, 'show'):
            print("✓ Basic Qt application creation successful")
        else:
            print("✗ Qt application or window creation failed")
            return False
        return True

    except Exception as e:
        print(f"✗ Basic Qt test failed: {e}")
        return False

def test_qt_web_components():
    """Test Qt web components that are missing."""
    print("\nTesting Qt web components...")

    try:
        from intellicrack.ui.dialogs.common_imports import QWebEngineView
        print("✓ QtWebEngineWidgets import successful")

        # Test actual usage
        app = QApplication.instance() or QApplication([])
        # Validate app instance
        if not app or not hasattr(app, 'exec_'):
            print("✗ Failed to create or get QApplication instance")
            return False

        web_view = QWebEngineView()
        web_view.setWindowTitle("Test WebEngine")
        print(f"✓ QWebEngineView instantiated: {type(web_view).__name__}")
        print(f"✓ QApplication validated: {type(app).__name__}")

        return True
    except ImportError as e:
        print(f"✗ QtWebEngineWidgets import failed: {e}")
        return False

def test_pyqtgraph():
    """Test pyqtgraph import."""
    print("\nTesting pyqtgraph...")

    try:
        import pyqtgraph
        print("✓ pyqtgraph import successful")

        # Test basic usage
        app = QApplication.instance() or QApplication([])
        plot_widget = pyqtgraph.PlotWidget()
        plot_widget.setWindowTitle("Test Plot")
        print(f"✓ pyqtgraph PlotWidget created: {type(plot_widget).__name__}")

        return True
    except ImportError as e:
        print(f"✗ pyqtgraph import failed: {e}")
        return False

def test_intellicrack_main_import():
    """Test if we can import the main Intellicrack components."""
    print("\nTesting Intellicrack main imports...")

    try:
        from intellicrack.ui.main_app import IntellicrackApp
        print("✓ IntellicrackApp import successful")

        # Test instantiation
        app = QApplication.instance() or QApplication([])
        intellicrack_app = IntellicrackApp()
        print(f"✓ IntellicrackApp instantiated: {type(intellicrack_app).__name__}")

        return True
    except ImportError as e:
        print(f"✗ IntellicrackApp import failed: {e}")
        return False

if __name__ == "__main__":
    print("Qt Component Test")
    print("=" * 40)

    basic_ok = test_qt_basic()
    web_ok = test_qt_web_components()
    graph_ok = test_pyqtgraph()
    main_ok = test_intellicrack_main_import()

    print("\n" + "=" * 40)
    print("Test Results:")
    print(f"Basic Qt: {'PASS' if basic_ok else 'FAIL'}")
    print(f"Qt Web Components: {'PASS' if web_ok else 'FAIL'}")
    print(f"pyqtgraph: {'PASS' if graph_ok else 'FAIL'}")
    print(f"IntellicrackApp: {'PASS' if main_ok else 'FAIL'}")

    if not web_ok or not graph_ok:
        print("\nCRITICAL: Missing components found!")
        print("Install with: pip install PyQtWebEngine pyqtgraph")
    else:
        print("\nAll components available!")
