#!/usr/bin/env python3
"""Test loading all tabs to ensure they work."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_ANGLE_PLATFORM'] = 'warp'
os.environ['QT_D3D_ADAPTER_INDEX'] = '1'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def test_tabs():
    """Test each tab individually."""
    try:
        print("Testing Intellicrack tabs...")

        from intellicrack.ui.dialogs.common_imports import QApplication
        app = QApplication(sys.argv)

        # Test shared context
        shared_context = {
            'main_window': None,
            'log_message': lambda x: print(f"[LOG] {x}"),
            'app_context': None,
            'task_manager': None
        }

        # Test each tab
        tabs_to_test = [
            ("DashboardTab", "intellicrack.ui.tabs.dashboard_tab"),
            ("AnalysisTab", "intellicrack.ui.tabs.analysis_tab"),
            ("ToolsTab", "intellicrack.ui.tabs.tools_tab"),
            ("ExploitationTab", "intellicrack.ui.tabs.exploitation_tab"),
            ("AIAssistantTab", "intellicrack.ui.tabs.ai_assistant_tab"),
            ("SettingsTab", "intellicrack.ui.tabs.settings_tab"),
        ]

        for tab_name, module_path in tabs_to_test:
            print(f"\nTesting {tab_name}...")
            try:
                module = __import__(module_path, fromlist=[tab_name])
                tab_class = getattr(module, tab_name)

                # Create instance
                tab = tab_class(shared_context)
                print(f"  ✓ {tab_name} created successfully")

                # Try to load content
                if hasattr(tab, 'lazy_load_content'):
                    tab.lazy_load_content()
                    print(f"  ✓ {tab_name} content loaded")

            except Exception as e:
                print(f"  ✗ {tab_name} failed: {e}")
                import traceback
                traceback.print_exc()

        print("\nTab testing complete!")
        return 0

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(test_tabs())
