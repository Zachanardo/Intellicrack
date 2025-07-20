"""Test script to identify all tab setup errors."""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set environment variables
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
os.environ['MKL_THREADING_LAYER'] = 'GNU'

print("Testing tab setup methods...")
print("=" * 50)

# Import the main app module
try:
    from intellicrack.ui.main_app import IntellicrackApp
    print("✓ IntellicrackApp imported successfully")
except Exception as e:
    print(f"✗ Failed to import IntellicrackApp: {e}")
    sys.exit(1)

# List of tab setup methods to check
tab_methods = [
    'setup_project_dashboard_tab',
    'setup_analysis_tab',
    'setup_patching_exploitation_tab',
    'setup_ai_assistant_tab',
    'setup_netanalysis_emulation_tab',
    'setup_tools_plugins_tab',
    'setup_binary_tools_tab',
    'setup_network_sim_tab',
    'setup_plugins_hub_tab',
    'setup_assistant_logs_tab',
    'setup_dashboard_tab',
    'setup_settings_tab',
    'setup_hex_viewer_tab',
    'setup_assistant_tab'
]

# Check which methods exist
print("\nChecking tab setup methods:")
for method in tab_methods:
    if hasattr(IntellicrackApp, method):
        print(f"✓ {method} exists")
    else:
        print(f"✗ {method} MISSING")

print("\nDone!")