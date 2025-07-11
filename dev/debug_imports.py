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

"""Debug imports to find what's blocking the GUI"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Debug: Starting import trace...")

# First, let's see what happens when we import main_app
print("\nDebug: About to import intellicrack.ui.main_app...")
from intellicrack.ui import main_app

print(f"\nDebug: main_app module imported successfully")
print(f"Debug: Module attributes count: {len(dir(main_app))}")

# Check if IntellicrackApp exists
if hasattr(main_app, 'IntellicrackApp'):
    print(f"Debug: IntellicrackApp found: {main_app.IntellicrackApp}")
else:
    print("Debug: IntellicrackApp NOT FOUND!")

# Check for launch function
if hasattr(main_app, 'launch'):
    print(f"Debug: launch function found: {main_app.launch}")
else:
    print("Debug: launch function NOT FOUND!")

print("\nDebug: Import complete. No exception thrown.")