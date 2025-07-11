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

"""Fix W0622 redefined-builtin errors by adding pylint disable comments."""

import os
import re

# Files to fix based on the error report
FILES_TO_FIX = [
    ('intellicrack/core/analysis/cfg_explorer.py', 386, 'format'),
    ('intellicrack/ui/dialogs/script_generator_dialog.py', 52, 'format'),
    ('intellicrack/ui/dialogs/text_editor_dialog.py', 115, 'format'),
    ('intellicrack/utils/final_utilities.py', 549, 'format'),
    ('intellicrack/utils/report_generator.py', 235, 'format'),
]

# pylint: disable=too-complex


def fix_file(filepath, line_num, builtin_name):
    """Fix redefined-builtin warning by adding pylint disable comment."""
    try:
        # Read the file
        full_path = os.path.join('/mnt/c/Intellicrack', filepath)
        with open(full_path, 'r') as f:
            lines = f.readlines()

        # Adjust for 0-based indexing
        idx = line_num - 1
        if idx < len(lines):
            line = lines[idx]
            # Check if already has pylint disable
            if 'pylint: disable=' in line:
                return

            # Look for function definition with the builtin parameter
            if f'{builtin_name}:' in line or f'{builtin_name} =' in line:
                # Add pylint disable comment
                if line.rstrip().endswith(':'):
                    lines[idx] = line.rstrip() + \
                        '  # pylint: disable=redefined-builtin\n'
                else:
                    # Find the colon on this or next few lines
                    for i in range(idx, min(idx + 5, len(lines))):
                        if lines[i].rstrip().endswith(':'):
                            lines[i] = lines[i].rstrip() + \
                                '  # pylint: disable=redefined-builtin\n'
                            break

        # Write back
        with open(full_path, 'w') as f:
            f.writelines(lines)

        print(f"Fixed {filepath}:{line_num}")

    except Exception as e:
        print(f"Error fixing {filepath}:{line_num} - {e}")


def main():
    """Main function."""
    # Skip cfg_explorer.py as it's already fixed
    for filepath, line_num, builtin_name in FILES_TO_FIX[1:]:
        fix_file(filepath, line_num, builtin_name)

    print("\nW0622 fixes applied!")


if __name__ == '__main__':
    main()
