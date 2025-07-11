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

"""Fix multi-line f-strings that are causing syntax errors."""

import glob
import os
import re


def fix_multiline_fstrings(filepath):
    """Fix multi-line f-strings in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines(keepends=True)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return 0

    modified = False
    fixes = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check if line contains an f-string with opening brace at end
        if 'f"' in line and line.rstrip().endswith('{'):
            # Find the complete f-string
            start_line = i
            brace_count = 1
            in_string = True
            j = i + 1

            # Count braces to find where the expression ends
            while j < len(lines) and brace_count > 0:
                for char_idx, char in enumerate(lines[j]):
                    if char == '{' and in_string:
                        brace_count += 1
                    elif char == '}' and in_string:
                        brace_count -= 1
                        if brace_count == 0:
                            # Found the closing brace
                            end_line = j
                            break
                    elif char == '"' and (char_idx == 0 or lines[j][char_idx-1] != '\\'):
                        # Check if this closes the f-string
                        if j > i:  # Multi-line string
                            in_string = False
                if brace_count == 0:
                    break
                j += 1

            if brace_count == 0:
                # Extract the complete f-string
                fstring_lines = lines[start_line:end_line+1]

                # Combine into single line, preserving the content
                combined = ''
                for idx, fline in enumerate(fstring_lines):
                    if idx == 0:
                        combined = fline.rstrip()
                    elif idx == len(fstring_lines) - 1:
                        combined += fline.strip()
                    else:
                        combined += fline.strip()

                # Clean up extra spaces
                combined = re.sub(r'\s+', ' ', combined)

                # Replace the multi-line f-string with single line version
                indent = len(lines[start_line]) - \
                    len(lines[start_line].lstrip())
                new_line = ' ' * indent + combined + '\n'

                # Record the fix
                fixes.append({
                    'line': start_line + 1,
                    'old': ''.join(fstring_lines),
                    'new': new_line
                })

                # Replace in the lines array
                lines[start_line:end_line+1] = [new_line]
                modified = True

                # Adjust index
                i = start_line

        i += 1

    if modified:
        # Write the fixed content back
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            print(f"\nFixed {len(fixes)} multi-line f-strings in {filepath}:")
            for fix in fixes:
                print(f"  Line {fix['line']}: Fixed multi-line f-string")

        except Exception as e:
            print(f"Error writing {filepath}: {e}")
            return 0

        return len(fixes)

    return 0


def main():
    """Main function to fix multi-line f-strings across the codebase."""
    print("Searching for multi-line f-strings in Python files...")

    total_fixes = 0
    files_checked = 0

    # Find all Python files
    for pattern in ['intellicrack/**/*.py', 'scripts/**/*.py', 'tests/**/*.py']:
        for filepath in glob.glob(pattern, recursive=True):
            files_checked += 1
            fixes = fix_multiline_fstrings(filepath)
            total_fixes += fixes

    print(f"\n{'='*60}")
    print(f"Summary: Fixed {total_fixes} multi-line f-strings")
    print(f"Files checked: {files_checked}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
