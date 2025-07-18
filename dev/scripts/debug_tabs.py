#!/usr/bin/env python3
"""Debug script to test tab imports"""

import sys
import os
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print("Testing tab imports...")

# Test each tab import separately
tabs_to_test = [
    ("DashboardTab", "intellicrack.ui.tabs.dashboard_tab"),
    ("AnalysisTab", "intellicrack.ui.tabs.analysis_tab"),
    ("ExploitationTab", "intellicrack.ui.tabs.exploitation_tab"),
    ("AIAssistantTab", "intellicrack.ui.tabs.ai_assistant_tab"),
    ("ToolsTab", "intellicrack.ui.tabs.tools_tab"),
    ("SettingsTab", "intellicrack.ui.tabs.settings_tab"),
]

for class_name, module_path in tabs_to_test:
    try:
        print(f"\nTrying to import {class_name} from {module_path}...")
        module = __import__(module_path, fromlist=[class_name])
        tab_class = getattr(module, class_name)
        print(f"✓ SUCCESS: {class_name} = {tab_class}")
    except Exception as e:
        print(f"✗ FAILED: {class_name} - {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

print("\nTesting BaseTab import...")
try:
    from intellicrack.ui.tabs.base_tab import BaseTab
    print(f"✓ BaseTab imported: {BaseTab}")
except Exception as e:
    print(f"✗ BaseTab import failed: {e}")
    import traceback
    traceback.print_exc()
