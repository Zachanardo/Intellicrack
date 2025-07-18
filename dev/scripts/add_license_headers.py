#!/usr/bin/env python3
"""
Script to add GPL v3 license headers to Python files missing them.
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
from pathlib import Path

GPL_HEADER_TEMPLATE = '''"""
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
'''

def has_license_header(file_path):
    """Check if file already has a license header."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(2000)  # Read first 2000 chars
            return any(marker in content for marker in [
                "Copyright (C) 2025 Zachary Flint",
                "GNU General Public License",
                "This program is free software"
            ])
    except Exception:
        return False

def add_license_header(file_path):
    """Add GPL license header to a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Skip if already has license
        if has_license_header(file_path):
            return False

        # Handle shebang lines
        lines = content.split('\n')
        header_lines = GPL_HEADER_TEMPLATE.strip().split('\n')

        insert_pos = 0
        # Keep shebang line at top if present
        if lines and lines[0].startswith('#!'):
            insert_pos = 1

        # Insert license header
        new_lines = lines[:insert_pos] + header_lines + [''] + lines[insert_pos:]
        new_content = '\n'.join(new_lines)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def scan_and_add_headers(directory):
    """Scan directory for Python files and add missing headers."""
    added_count = 0
    skipped_count = 0

    for py_file in Path(directory).rglob("*.py"):
        # Skip virtual environments and hidden directories
        if any(part.startswith('.') for part in py_file.parts):
            continue
        if 'site-packages' in str(py_file):
            continue

        if add_license_header(py_file):
            print(f"Added header to: {py_file}")
            added_count += 1
        else:
            print(f"Skipped (already has header): {py_file}")
            skipped_count += 1

    print(f"\nSummary: Added headers to {added_count} files, skipped {skipped_count} files")
    return added_count, skipped_count

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python add_license_headers.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        sys.exit(1)

    scan_and_add_headers(directory)
