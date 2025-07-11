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

"""Fix the try/except imbalance in main_app.py"""

import re


# pylint: disable=too-complex
def fix_try_except_imbalance():
    """Fix try/except imbalance in main_app.py by removing orphaned except blocks."""
    with open('intellicrack/ui/main_app.py', 'r', encoding='utf-8') as f:
        content = f.read()

    lines = content.split('\n')

    # Track try/except balance and find orphaned except blocks
    try_stack = []  # Stack of try block indentations
    new_lines = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        indent_level = len(line) - len(line.lstrip())

        if stripped.startswith('try:'):
            try_stack.append(indent_level)
            new_lines.append(line)
        elif stripped.startswith('except '):
            if try_stack:
                # Check if this except matches the most recent try
                last_try_indent = try_stack[-1]
                if indent_level == last_try_indent:
                    # This except matches the try, remove try from stack
                    try_stack.pop()
                    new_lines.append(line)
                elif indent_level < last_try_indent:
                    # This except is at a higher level, might match an earlier try
                    # Find matching try
                    found_match = False
                    for j in range(len(try_stack) - 1, -1, -1):
                        if try_stack[j] == indent_level:
                            # Remove this try and all nested tries
                            try_stack = try_stack[:j]
                            new_lines.append(line)
                            found_match = True
                            break

                    if not found_match:
                        print(
                            f"Line {i+1}: Orphaned except block removed: {line.strip()}")
                        # Skip this orphaned except block
                        continue
                else:
                    # This except is more indented than the try, likely orphaned
                    print(
                        f"Line {i+1}: Orphaned except block removed: {line.strip()}")
                    continue
            else:
                # No try blocks on stack, this is orphaned
                print(
                    f"Line {i+1}: Orphaned except block removed: {line.strip()}")
                continue
        elif stripped.startswith('finally:'):
            if try_stack:
                # Finally doesn't pop the try, but we note it
                new_lines.append(line)
            else:
                print(
                    f"Line {i+1}: Orphaned finally block removed: {line.strip()}")
                continue
        else:
            new_lines.append(line)

    # Write the fixed content
    with open('intellicrack/ui/main_app.py', 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))

    print(
        f"Fixed try/except imbalance. Remaining try blocks: {len(try_stack)}")


if __name__ == '__main__':
    fix_try_except_imbalance()
