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

"""Trace execution to find where the app stops"""

import sys
import os

print("=== EXECUTION TRACE ===")

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("\n1. Testing launch_intellicrack.py flow...")
try:
    print("   - Importing launch_intellicrack...")
    import launch_intellicrack
    print("   ✓ launch_intellicrack imported")
    
    # Don't call main() as it will run the full app
    print("   - Checking if __name__ == '__main__' block exists...")
    
except Exception as e:
    print(f"   ✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n2. Testing intellicrack.main flow...")
try:
    print("   - Importing intellicrack.main...")
    from intellicrack.main import main
    print("   ✓ intellicrack.main.main imported")
    
    # Check what happens when we call main
    print("\n3. Calling main() with tracing...")
    
    # Monkey-patch the launch function to trace it
    original_launch = None
    
    def trace_launch():
        print("   [TRACE] launch() was called!")
        print("   [TRACE] Returning 0 instead of running Qt")
        return 0
    
    # Replace launch with our tracer
    from intellicrack.ui import main_app
    original_launch = main_app.launch
    main_app.launch = trace_launch
    
    # Now call main
    print("   - Calling main()...")
    result = main()
    print(f"   ✓ main() returned: {result}")
    
    # Restore original
    main_app.launch = original_launch
    
except Exception as e:
    print(f"   ✗ Error in main: {e}")
    import traceback
    traceback.print_exc()

print("\n4. Checking module-level code...")
# Check if any module is running code at import time that might exit
print("   - Checking for sys.exit calls...")

import ast
import inspect

def check_for_exit_calls(module_path):
    """Check if a module has sys.exit calls at module level"""
    try:
        with open(module_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'sys' and 
                        node.func.attr == 'exit'):
                        # Check if it's at module level (not in a function)
                        return True
                elif isinstance(node.func, ast.Name) and node.func.id == 'exit':
                    return True
    except:
        pass
    return False

# Check key files
files_to_check = [
    'launch_intellicrack.py',
    'intellicrack/main.py',
    'intellicrack/ui/main_app.py'
]

for file_path in files_to_check:
    if os.path.exists(file_path):
        has_exit = check_for_exit_calls(file_path)
        print(f"   - {file_path}: {'Has sys.exit at module level!' if has_exit else 'OK'}")

print("\n=== TRACE COMPLETE ===")