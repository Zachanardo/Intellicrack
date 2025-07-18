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

"""Direct launcher to bypass launch_intellicrack.py"""

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=== DIRECT LAUNCH ===")
print("Bypassing launch_intellicrack.py")

# Set environment for safety
os.environ['QT_OPENGL'] = 'software'
os.environ['INTELLICRACK_NO_SPLASH'] = '1'

try:
    print("\n1. Importing and calling main directly...")
    from intellicrack.main import main
    print("   - main imported")

    print("\n2. Calling main()...")
    exit_code = main()
    print(f"\n3. main() returned: {exit_code}")

except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n=== END ===")
