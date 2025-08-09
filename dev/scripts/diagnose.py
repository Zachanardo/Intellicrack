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

"""Diagnostic script to find where execution stops"""

import sys
import os

print("=== INTELLICRACK DIAGNOSTIC ===")
print("Python:", sys.version)
print("Working directory:", os.getcwd())

# Test basic imports
print("\n1. Testing basic imports...")
try:
    from intellicrack.core.startup_checks import perform_startup_checks
    print("   ✓ startup_checks imported")
except Exception as e:
    print(f"   ✗ Failed to import startup_checks: {e}")
    sys.exit(1)

# Test startup checks with timeout
print("\n2. Running startup checks with timeout...")
import signal
import time

def timeout_handler(signum, frame):
    print("\n   ✗ TIMEOUT: Startup checks took too long!")
    print("   This suggests the application is hanging during initialization.")
    sys.exit(1)

# Set a 10-second timeout
if hasattr(signal, 'SIGALRM'):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(10)
else:
    print("   Note: Timeout not available on Windows")

try:
    start_time = time.time()
    perform_startup_checks()
    elapsed = time.time() - start_time
    print(f"   ✓ Startup checks completed in {elapsed:.2f} seconds")
except Exception as e:
    print(f"   ✗ Startup checks failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Cancel timeout
if hasattr(signal, 'SIGALRM'):
    signal.alarm(0)

# Test GUI import
print("\n3. Testing GUI import...")
try:
    from intellicrack.ui.main_app import launch
    print("   ✓ GUI launch function imported")
except Exception as e:
    print(f"   ✗ Failed to import GUI: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test Qt
print("\n4. Testing Qt...")
try:
    from intellicrack.ui.dialogs.common_imports import QApplication, QMainWindow
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    print("   ✓ Qt initialized successfully")

    # Test creating a simple window
    
    window = QMainWindow()
    window.setWindowTitle("Test")
    print("   ✓ Test window created")

except Exception as e:
    print(f"   ✗ Qt test failed: {e}")
    import traceback
    traceback.print_exc()

print("\n=== DIAGNOSTIC COMPLETE ===")
print("If this script completes but the app doesn't start,")
print("the issue is likely in the launch() function or window creation.")
