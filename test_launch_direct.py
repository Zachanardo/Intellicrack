#!/usr/bin/env python3
"""Test launching Intellicrack directly with launch function."""

import os
import sys

# Set Qt to offscreen mode for WSL
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from intellicrack.ui.main_app import launch
    print("Launch function imported successfully!")
    
    # Try to launch the app
    print("Attempting to launch Intellicrack...")
    launch()
    
except Exception as e:
    print(f"Error launching app: {e}")
    import traceback
    traceback.print_exc()