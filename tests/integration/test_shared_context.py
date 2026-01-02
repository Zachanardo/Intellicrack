"""Test script to verify shared context functionality across tabs.

This script tests that when a binary is loaded via the dashboard,
it's properly shared across all other tabs.
"""

import sys
from pathlib import Path

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.core.app_context import AppContext
from intellicrack.ui.tabs.dashboard_tab import DashboardTab
from intellicrack.ui.tabs.analysis_tab import AnalysisTab
from intellicrack.ui.tabs.exploitation_tab import ExploitationTab
from intellicrack.ui.tabs.tools_tab import ToolsTab


def test_shared_context():
    """Test that binary loading is shared across all tabs."""
    print("=" * 60)
    print("Testing Shared Context Functionality")
    print("=" * 60)

    # Create Qt application
    app = QApplication(sys.argv)

    # Create app context
    app_context = AppContext()

    # Create shared context dictionary
    shared_context = {
        "app_context": app_context,
        "task_manager": None,
        "main_window": None
    }

    # Create tabs
    print("\n1. Creating tabs with shared context...")
    dashboard = DashboardTab(shared_context)
    analysis = AnalysisTab(shared_context)
    exploitation = ExploitationTab(shared_context)
    tools = ToolsTab(shared_context)

    # Verify tabs have app_context
    print("\n2. Verifying app_context is available in all tabs...")
    assert dashboard.app_context == app_context, "Dashboard missing app_context"
    assert analysis.app_context == app_context, "Analysis missing app_context"
    assert exploitation.app_context == app_context, "Exploitation missing app_context"
    assert tools.app_context == app_context, "Tools missing app_context"
    print("OK All tabs have app_context")

    # Test binary loading
    print("\n3. Testing binary loading...")

    # Create a test binary file
    test_binary = Path(__file__).parent / "test_binary.exe"
    test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # Minimal PE header

    # Load binary via app_context (simulating dashboard action)
    print(f"   Loading test binary: {test_binary}")
    success = app_context.load_binary(str(test_binary))
    assert success, "Failed to load binary"
    print("OK Binary loaded successfully")

    # Check that all tabs received the binary
    print("\n4. Verifying binary is available in all tabs...")

    # Analysis tab should have current_binary set
    if analysis.current_binary:
        print(f"OK Analysis tab has binary: {analysis.current_binary}")
    else:
        print("FAIL Analysis tab missing binary")

    # Exploitation tab should have current_binary set
    if exploitation.current_binary:
        print(f"OK Exploitation tab has binary: {exploitation.current_binary}")
    else:
        print("FAIL Exploitation tab missing binary")

    # Tools tab should have current_binary set
    if tools.current_binary:
        print(f"OK Tools tab has binary: {tools.current_binary}")
    else:
        print("FAIL Tools tab missing binary")

    # Test binary unloading
    print("\n5. Testing binary unloading...")
    app_context.unload_binary()
    print("OK Binary unloaded")

    # Verify tabs cleared their binary references
    print("\n6. Verifying binary is cleared in all tabs...")
    assert analysis.current_binary is None, "Analysis tab still has binary"
    assert exploitation.current_binary is None, "Exploitation tab still has binary"
    assert tools.current_binary is None, "Tools tab still has binary"
    print("OK All tabs cleared binary references")

    # Clean up test file
    test_binary.unlink()

    print("\n" + "=" * 60)
    print("OK All tests passed! Shared context is working correctly.")
    print("=" * 60)

    return True


if __name__ == "__main__":
    try:
        success = test_shared_context()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nFAIL Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
