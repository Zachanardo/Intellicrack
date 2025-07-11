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

"""
Check for dependency conflicts in requirements.txt without installing
"""
import os
import subprocess
import sys
import tempfile


def check_conflicts(requirements_file):
    """Check for dependency conflicts using pip-compile dry run"""
    print(f"Checking dependencies in {requirements_file}...")

    # Method 1: Use pip check (if packages were installed)
    # print("\n=== Method 1: pip check ===")
    # subprocess.run([sys.executable, "-m", "pip", "check"])

    # Method 2: Use pip install --dry-run (shows conflicts)
    print("\n=== Checking for conflicts with pip install --dry-run ===")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install",
            "--dry-run", "-r", requirements_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Conflicts found:")
        print(result.stderr)
    else:
        print("No conflicts detected!")

    # Method 3: Use pipdeptree to show dependency tree
    print("\n=== Installing pipdeptree for better analysis ===")
    subprocess.run([sys.executable, "-m", "pip", "install",
                   "pipdeptree"], capture_output=True)

    print("\n=== Dependency tree ===")
    subprocess.run([sys.executable, "-m", "pipdeptree", "--warn", "fail"])


if __name__ == "__main__":
    requirements_file = "requirements.txt"
    if len(sys.argv) > 1:
        requirements_file = sys.argv[1]

    check_conflicts(requirements_file)
