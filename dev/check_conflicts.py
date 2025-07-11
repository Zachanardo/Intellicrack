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

"""Check for all dependency conflicts without installing"""
import re
import subprocess
import sys

print("Checking requirements.txt for conflicts...\n")

# First check for duplicate packages
print("1. Checking for duplicate package entries...")
packages = {}
with open('../requirements.txt', 'r') as f:
    for line_num, line in enumerate(f, 1):
        line = line.strip()
        if line and not line.startswith('#'):
            # Extract package name
            match = re.match(r'^([a-zA-Z0-9\-_\.]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                if pkg_name in packages:
                    print(
                        f"   DUPLICATE: {pkg_name} on lines {packages[pkg_name]} and {line_num}")
                else:
                    packages[pkg_name] = line_num

if not any(pkg in packages for pkg in packages if list(packages.values()).count(packages[pkg]) > 1):
    print("   ✓ No duplicates found")

# Now test with pip
print("\n2. Checking for version conflicts with pip...")
result = subprocess.run(
    [sys.executable, "-m", "pip", "install",
        "--dry-run", "-r", "../requirements.txt"],
    capture_output=True,
    text=True
)

# Look for conflicts in output
if "ERROR: Cannot install" in result.stderr:
    print("   CONFLICTS FOUND:")
    lines = result.stderr.split('\n')
    for i, line in enumerate(lines):
        if 'ERROR:' in line or 'The conflict is caused by:' in line:
            print(f"   {line}")
            # Print next few lines for context
            for j in range(1, 5):
                if i+j < len(lines) and lines[i+j].strip():
                    print(f"   {lines[i+j]}")
else:
    print("   ✓ No version conflicts detected")

print("\nDone!")
