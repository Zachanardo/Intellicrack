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

import os
import sys
import subprocess

# Get all Python files
python_files = []
for root, dirs, files in os.walk('intellicrack'):
    # Skip certain directories
    if any(skip in root for skip in ['__pycache__', '.git', 'venv']):
        continue
    for file in files:
        if file.endswith('.py'):
            python_files.append(os.path.join(root, file))

# Run vulture on all files together
print(f"Scanning {len(python_files)} Python files...")
try:
    cmd = [sys.executable, "-m", "vulture"] + python_files
    subprocess.run(cmd, check=False)
except Exception as e:
    print(f"Error running vulture: {e}")