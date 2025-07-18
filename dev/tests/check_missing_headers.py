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

import sys
from pathlib import Path


def check_license_header(file_path):
    """Check if file has license header."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(2000)
            return "Copyright (C) 2025 Zachary Flint" in content
    except Exception:
        return False

def find_files_without_headers(directory):
    """Find Python files without license headers."""
    missing_headers = []

    for py_file in Path(directory).rglob("*.py"):
        # Skip virtual environments and hidden directories
        if any(part.startswith('.') for part in py_file.parts):
            continue
        if 'site-packages' in str(py_file):
            continue
        if 'conflict_test' in str(py_file):
            continue

        if not check_license_header(py_file):
            missing_headers.append(str(py_file))

    return missing_headers

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_missing_headers.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    missing = find_files_without_headers(directory)

    print(f"Found {len(missing)} files without license headers:")
    for file_path in missing:
        print(file_path)
