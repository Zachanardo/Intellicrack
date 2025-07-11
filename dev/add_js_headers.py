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

import os
import sys
from pathlib import Path

JS_HEADER_TEMPLATE = '''/*
 * This file is part of Intellicrack.
 * Copyright (C) 2025 Zachary Flint
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

'''

def check_file_writable(file_path):
    """Check if file is writable using os module."""
    try:
        # Use os.access to check write permissions
        if not os.path.exists(file_path):
            return False
        return os.access(file_path, os.W_OK)
    except Exception:
        return False

def has_license_header(file_path):
    """Check if file already has a license header."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read(1000)
            return "Copyright (C) 2025 Zachary Flint" in content
    except Exception:
        return False

def add_license_header(file_path):
    """Add GPL license header to a JS file."""
    try:
        # Check if file is writable before attempting modification
        if not check_file_writable(file_path):
            print(f"Warning: {file_path} is not writable")
            return False

        # Get file stats using os module
        file_stats = os.stat(file_path)
        original_mode = file_stats.st_mode

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if has_license_header(file_path):
            return False

        new_content = JS_HEADER_TEMPLATE + content

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        # Preserve original file permissions using os.chmod
        os.chmod(file_path, original_mode)

        return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def scan_and_add_headers(directory):
    """Scan directory for JS files and add missing headers."""
    added_count = 0
    skipped_count = 0

    # Check for environment variable to control verbosity
    verbose = os.environ.get('INTELLICRACK_VERBOSE', 'false').lower() == 'true'

    # Resolve directory path using os.path for cross-platform compatibility
    directory = os.path.abspath(directory)

    for js_file in Path(directory).rglob("*.js"):
        if 'node_modules' in str(js_file):
            continue

        if add_license_header(js_file):
            if verbose:
                print(f"Added header to: {js_file}")
            added_count += 1
        else:
            if verbose:
                print(f"Skipped (already has header): {js_file}")
            skipped_count += 1

    print(f"\nSummary: Added headers to {added_count} files, skipped {skipped_count} files")
    return added_count, skipped_count

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python add_js_headers.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    scan_and_add_headers(directory)
