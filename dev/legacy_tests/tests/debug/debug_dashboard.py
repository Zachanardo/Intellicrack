#!/usr/bin/env python3
"""Debug the DashboardTab initialization."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_dashboard_tab():
    """Test creating DashboardTab."""
    try:
        print("1. Importing Qt...")
        from PyQt6.QtWidgets import QApplication
        print("   ✓ Qt imported")

        print("2. Creating QApplication...")
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        print("3. Testing DashboardTab...")
        from intellicrack.ui.tabs.dashboard_tab import DashboardTab
        print("   - Import successful")

        print("4. Creating DashboardTab with minimal context...")
        shared_context = {}
        tab = DashboardTab(shared_context)
        print("   ✓ DashboardTab created")

        print("5. Calling lazy_load_content...")
        tab.lazy_load_content()
        print("   ✓ lazy_load_content completed")

        return 0

    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    print("Testing DashboardTab...")
    result = test_dashboard_tab()
    print(f"Test completed with exit code: {result}")
    sys.exit(result)
