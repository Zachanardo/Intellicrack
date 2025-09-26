"""Test script to verify all GUI fixes are working correctly."""

import sys
import os
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.handlers.pyqt6_handler import QApplication, QMainWindow, QTabWidget
from intellicrack.core.app_context import AppContext
from intellicrack.ui.tabs.dashboard_tab import DashboardTab
from intellicrack.ui.tabs.analysis_tab import AnalysisTab
from intellicrack.ui.tabs.exploitation_tab import ExploitationTab
from intellicrack.ui.tabs.tools_tab import ToolsTab
from intellicrack.ui.widgets.cpu_status_widget import CPUStatusWidget
from intellicrack.ui.widgets.gpu_status_widget import GPUStatusWidget


def test_gui_fixes():
    """Test all GUI fixes are working correctly."""
    print("=" * 60)
    print("Testing All GUI Fixes")
    print("=" * 60)

    # Create Qt application
    app = QApplication(sys.argv)

    # Create main window for testing
    main_window = QMainWindow()
    main_window.setWindowTitle("Intellicrack GUI Test")
    main_window.resize(1400, 900)

    # Create app context
    app_context = AppContext()

    # Create shared context dictionary
    shared_context = {
        "app_context": app_context,
        "task_manager": None,
        "main_window": main_window
    }

    # Create tab widget
    tab_widget = QTabWidget()

    # Test 1: Create tabs with shared context
    print("\n1. Testing tab creation with shared context...")
    dashboard = DashboardTab(shared_context)
    analysis = AnalysisTab(shared_context)
    exploitation = ExploitationTab(shared_context)
    tools = ToolsTab(shared_context)

    # Add tabs to widget
    tab_widget.addTab(dashboard, "Dashboard")
    tab_widget.addTab(analysis, "Analysis")
    tab_widget.addTab(exploitation, "Exploitation")
    tab_widget.addTab(tools, "Tools")

    print("✓ All tabs created successfully")

    # Test 2: Verify CPU status widget has scroll area
    print("\n2. Testing CPU status widget...")
    cpu_widget = CPUStatusWidget()

    # Check for scroll area
    scroll_found = False
    for child in cpu_widget.children():
        if child.__class__.__name__ == "QScrollArea":
            scroll_found = True
            break

    if scroll_found:
        print("✓ CPU status widget has scroll area")
    else:
        print("✗ CPU status widget missing scroll area")

    # Test 3: Verify GPU status widget has scroll area and timer
    print("\n3. Testing GPU status widget...")
    gpu_widget = GPUStatusWidget()

    # Check for scroll area
    scroll_found = False
    for child in gpu_widget.children():
        if child.__class__.__name__ == "QScrollArea":
            scroll_found = True
            break

    if scroll_found:
        print("✓ GPU status widget has scroll area")
    else:
        print("✗ GPU status widget missing scroll area")

    # Check for monitoring thread
    if hasattr(gpu_widget, 'monitor_thread') and gpu_widget.monitor_thread:
        print("✓ GPU status widget has monitoring thread")
    else:
        print("✗ GPU status widget missing monitoring thread")

    # Test 4: Verify button styling in dashboard
    print("\n4. Testing dashboard button styling...")

    # Check for button existence and styling
    buttons_checked = 0
    for button_name in ["open_file_btn", "open_project_btn", "attach_process_btn"]:
        if hasattr(dashboard, button_name):
            button = getattr(dashboard, button_name)
            style = button.styleSheet()
            if "background-color" in style and "text-shadow" in style:
                print(f"✓ {button_name} has enhanced styling")
                buttons_checked += 1
            else:
                print(f"✗ {button_name} missing enhanced styling")
        else:
            print(f"✗ {button_name} not found")

    if buttons_checked >= 3:
        print("✓ All main buttons have enhanced styling")

    # Test 5: Test binary loading and shared context
    print("\n5. Testing shared context for binary loading...")

    # Create a test binary file
    test_binary = Path(__file__).parent / "test_binary.exe"
    test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # Minimal PE header

    # Load binary via app_context
    success = app_context.load_binary(str(test_binary))
    if success:
        print("✓ Binary loaded successfully")

        # Check if tabs received the binary
        tabs_with_binary = 0
        if analysis.current_binary:
            print("✓ Analysis tab has binary")
            tabs_with_binary += 1
        if exploitation.current_binary:
            print("✓ Exploitation tab has binary")
            tabs_with_binary += 1
        if tools.current_binary:
            print("✓ Tools tab has binary")
            tabs_with_binary += 1

        if tabs_with_binary >= 3:
            print("✓ All tabs received binary via shared context")
        else:
            print(f"✗ Only {tabs_with_binary}/3 tabs received binary")

        # Clean up
        app_context.unload_binary()
        test_binary.unlink()
    else:
        print("✗ Failed to load test binary")

    # Test 6: Check for attach process button rename
    print("\n6. Testing button rename...")
    if hasattr(dashboard, 'attach_process_btn'):
        button_text = dashboard.attach_process_btn.text()
        if "Attach to Running Process" in button_text:
            print("✓ Button renamed to 'Attach to Running Process'")
        else:
            print(f"✗ Button text is '{button_text}', expected 'Attach to Running Process'")
    else:
        print("✗ attach_process_btn not found")

    # Show main window for visual inspection
    main_window.setCentralWidget(tab_widget)
    main_window.show()

    print("\n" + "=" * 60)
    print("✅ GUI Test Complete! Check the window for visual verification.")
    print("=" * 60)
    print("\nPlease verify visually:")
    print("- CPU and GPU widgets should be scrollable with full content visible")
    print("- Buttons should have good contrast with darker backgrounds")
    print("- No emoji on 'Attach to Running Process' button")
    print("- GPU widget should show live updating data")
    print("- System monitor graphs should show independent CPU/memory data")

    # Run the application
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(test_gui_fixes())
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
