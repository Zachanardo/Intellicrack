#!/usr/bin/env python3
"""Test creating the monitoring widgets that might be causing the hang."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_monitoring_widgets():
    """Test creating monitoring widgets."""
    try:
        print("1. Importing Qt...")
        from PyQt6.QtWidgets import QApplication, QMainWindow
        print("   ✓ Qt imported")

        print("2. Creating QApplication...")
        app = QApplication(sys.argv)
        print("   ✓ QApplication created")

        # Try to import and create each widget
        try:
            print("3. Testing SystemMonitorWidget...")
            from intellicrack.ui.widgets.system_monitor_widget import SystemMonitorWidget
            print("   - Import successful")
            widget = SystemMonitorWidget()
            print("   ✓ SystemMonitorWidget created")
        except Exception as e:
            print(f"   ✗ SystemMonitorWidget error: {e}")
            import traceback
            traceback.print_exc()

        try:
            print("4. Testing GPUStatusWidget...")
            from intellicrack.ui.widgets.gpu_status_widget import GPUStatusWidget
            print("   - Import successful")
            widget = GPUStatusWidget()
            print("   ✓ GPUStatusWidget created")
        except Exception as e:
            print(f"   ✗ GPUStatusWidget error: {e}")
            import traceback
            traceback.print_exc()

        try:
            print("5. Testing CPUStatusWidget...")
            from intellicrack.ui.widgets.cpu_status_widget import CPUStatusWidget
            print("   - Import successful")
            widget = CPUStatusWidget()
            print("   ✓ CPUStatusWidget created")
        except Exception as e:
            print(f"   ✗ CPUStatusWidget error: {e}")
            import traceback
            traceback.print_exc()

        return 0

    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    print("Testing monitoring widgets...")
    result = test_monitoring_widgets()
    print(f"Test completed with exit code: {result}")
    sys.exit(result)
