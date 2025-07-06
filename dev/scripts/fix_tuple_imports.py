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
Fix missing Tuple imports in Intellicrack codebase.

This script finds all files that use Tuple[] type annotations
and ensures they have the proper import from typing.
"""

import re
import sys
from pathlib import Path


def find_files_with_tuple_usage():
    """Find all Python files that use Tuple[] but may be missing the import."""
    project_root = Path(__file__).parent
    files_with_tuple = []

    for file_path in project_root.rglob("*.py"):
        if "tests/" in str(file_path):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file uses Tuple[] annotation
            if re.search(r'\bTuple\[', content):
                files_with_tuple.append(file_path)

        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    return files_with_tuple


def has_tuple_import(content):
    """Check if file already has Tuple import."""
    # Check for various forms of Tuple import
    patterns = [
        r'from typing import.*\bTuple\b',
        r'from typing import.*,.*\bTuple\b',
        r'import typing.*',  # typing.Tuple usage
    ]

    for pattern in patterns:
        if re.search(pattern, content):
            return True
    return False


def fix_tuple_import(file_path):
    """Fix Tuple import in a specific file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Skip if already has Tuple import
        if has_tuple_import(content):
            return True, "Already has Tuple import"

        lines = content.split('\n')

        # Find the best place to add the import
        import_line_index = -1
        typing_import_line = -1

        for i, line in enumerate(lines):
            # Look for existing typing imports
            if re.match(r'^from typing import', line.strip()):
                typing_import_line = i
                break
            # Look for other imports as fallback
            elif re.match(r'^(import|from)', line.strip()):
                import_line_index = i

        if typing_import_line != -1:
            # Add Tuple to existing typing import
            line = lines[typing_import_line]
            if 'Tuple' not in line:
                # Add Tuple to the import list
                if line.endswith(')'):
                    # Multi-line import
                    lines[typing_import_line] = line[:-1] + ', Tuple)'
                else:
                    # Single line import
                    lines[typing_import_line] = line + ', Tuple'
        else:
            # Add new typing import
            insert_index = import_line_index + 1 if import_line_index != -1 else 0
            lines.insert(insert_index, 'from typing import Tuple')

        # Write back to file
        new_content = '\n'.join(lines)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        return True, "Fixed Tuple import"

    except Exception as e:
        return False, f"Error: {e}"


def main():
    """Main function to fix all Tuple imports."""
    print("Finding files with Tuple usage...")
    files_with_tuple = find_files_with_tuple_usage()

    print(f"Found {len(files_with_tuple)} files with Tuple usage")

    fixed_count = 0
    error_count = 0

    for file_path in files_with_tuple:
        print(f"Processing: {file_path}")

        success, message = fix_tuple_import(file_path)

        if success:
            if "Fixed" in message:
                fixed_count += 1
            print(f"  ✓ {message}")
        else:
            error_count += 1
            print(f"  ❌ {message}")

    print("\nSummary:")
    print(f"  Files processed: {len(files_with_tuple)}")
    print(f"  Files fixed: {fixed_count}")
    print(f"  Files with errors: {error_count}")
    print(
        f"  Files already correct: {len(files_with_tuple) - fixed_count - error_count}")

    return 0 if error_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
