#!/usr/bin/env python3
"""FINAL indentation fix - brute force approach.

This will fix the exact patterns causing syntax errors.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
import re

def fix_file_completely(filepath):
    """Completely fix indentation in a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')
        fixed_lines = []

        i = 0
        while i < len(lines):
            line = lines[i]

            # Special case: comments followed by unindented code
            if (i > 0 and
                (lines[i-1].strip().startswith('#') or
                 lines[i-1].strip() == '"""' or
                 lines[i-1].strip().endswith('"""')) and
                line.strip() and
                not line.startswith('    ') and
                not line.strip().startswith(('import ', 'from ', 'class ', 'def ', '@', '#'))):

                # Find proper indentation level
                indent_level = 4
                for j in range(i-1, -1, -1):
                    if lines[j].strip().startswith(('def ', 'class ')):
                        base_indent = len(lines[j]) - len(lines[j].lstrip())
                        indent_level = base_indent + 4
                        break

                fixed_lines.append(' ' * indent_level + line.strip())

            # Special case: try: followed by unindented code
            elif (i > 0 and
                  lines[i-1].strip().endswith(':') and
                  ('try' in lines[i-1] or 'except' in lines[i-1] or 'else' in lines[i-1] or 'finally' in lines[i-1]) and
                  line.strip() and
                  not line.startswith('    ')):

                # Get base indentation from try line
                base_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                fixed_lines.append(' ' * (base_indent + 4) + line.strip())

            # Special case: function/class definitions followed by unindented docstring/code
            elif (i > 0 and
                  lines[i-1].strip().endswith(':') and
                  ('def ' in lines[i-1] or 'class ' in lines[i-1]) and
                  line.strip() and
                  not line.startswith('    ')):

                # Get base indentation from def/class line
                base_indent = len(lines[i-1]) - len(lines[i-1].lstrip())
                fixed_lines.append(' ' * (base_indent + 4) + line.strip())

            else:
                fixed_lines.append(line)

            i += 1

        # Write back the fixed content
        fixed_content = '\n'.join(fixed_lines)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(fixed_content)

        return True

    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False

def main():
    os.chdir('C:/Intellicrack')

    # Get all Python files with syntax errors
    import subprocess
    try:
        result = subprocess.run([
            'python', '-c',
            '''import os, ast
files = []
for root, dirs, files_list in os.walk("intellicrack"):
    for file in files_list:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    ast.parse(f.read())
            except SyntaxError:
                files.append(path)
            except:
                pass
for f in files:
    print(f)'''
        ], capture_output=True, text=True, cwd='C:/Intellicrack')

        error_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]

    except Exception as e:
        print(f"Error getting file list: {e}")
        return

    print(f"Found {len(error_files)} files with syntax errors")
    print("Fixing files...")

    # Fix files in smaller batches
    batch_size = 20
    for i in range(0, len(error_files), batch_size):
        batch = error_files[i:i+batch_size]
        print(f"Processing batch {i//batch_size + 1}: {len(batch)} files")

        for filepath in batch:
            if os.path.exists(filepath):
                print(f"  Fixing {filepath}")
                fix_file_completely(filepath)

    print("All files processed.")

if __name__ == "__main__":
    main()
