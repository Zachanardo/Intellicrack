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

import subprocess
import sys

print("Testing all dependencies for conflicts...")
result = subprocess.run(
    [sys.executable, "-m", "pip", "install",
        "-r", "requirements.txt", "--dry-run"],
    capture_output=True,
    text=True
)

# Parse output for conflicts
lines = result.stderr.split('\n')
in_error = False
for i, line in enumerate(lines):
    if 'ERROR:' in line and 'Cannot install' in line:
        in_error = True
        print('\n' + '='*60)
    if in_error and line.strip() == '':
        in_error = False
    if in_error or 'ERROR:' in line:
        print(line)

if result.returncode == 0:
    print("\nNo conflicts found! All dependencies are compatible.")
