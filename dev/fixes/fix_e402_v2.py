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

"""Script to fix E402 import order issues by moving imports after docstrings."""

import re
import sys
from pathlib import Path


def fix_imports_in_file(filepath: Path) -> bool:
    """Fix import order in a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        lines = content.split('\n')

        # Patterns to identify imports
        import_pattern = re.compile(r'^\s*(import\s+|from\s+\S+\s+import)')

        # Find where docstring ends
        docstring_end = 0
        in_docstring = False
        docstring_delim = None

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines and comments at the start
            if i == 0 and stripped.startswith('#!'):
                docstring_end = 1
                continue
            if i <= 1 and (stripped.startswith('# -*- coding') or stripped.startswith('# coding')):
                docstring_end = i + 1
                continue

            # Check for docstring
            if not in_docstring:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    docstring_delim = '"""' if stripped.startswith(
                        '"""') else "'''"
                    if stripped.count(docstring_delim) >= 2:
                        # Single line docstring
                        docstring_end = i + 1
                        break
                    else:
                        # Multi-line docstring start
                        in_docstring = True
            else:
                if docstring_delim in line:
                    # End of multi-line docstring
                    docstring_end = i + 1
                    break

        # Collect all imports that appear after the docstring
        imports = []
        other_lines = []

        i = docstring_end
        # Skip empty lines after docstring
        while i < len(lines) and lines[i].strip() == '':
            i += 1

        # Collect imports and non-imports
        while i < len(lines):
            line = lines[i]
            if import_pattern.match(line):
                imports.append(line)
                i += 1
            elif line.strip() == '' and i + 1 < len(lines) and import_pattern.match(lines[i + 1]):
                # Empty line before an import
                i += 1
            else:
                # Found non-import line, collect the rest
                other_lines = lines[i:]
                break

        # If no reordering needed, return
        if not imports or i == len(lines):
            return False

        # Rebuild the file
        new_lines = lines[:docstring_end]

        # Add empty line after docstring if needed
        if docstring_end > 0 and new_lines and new_lines[-1].strip() != '':
            new_lines.append('')

        # Add all imports
        new_lines.extend(imports)

        # Add empty line after imports if needed
        if imports and other_lines and other_lines[0].strip() != '':
            new_lines.append('')

        # Add the rest
        new_lines.extend(other_lines)

        # Write back
        new_content = '\n'.join(new_lines)

        if new_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True

        return False

    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False


def main():
    """Fix E402 in all Python files."""
    root = Path('/mnt/c/Intellicrack')
    fixed = 0

    for py_file in root.rglob('*.py'):
        if 'venv' in str(py_file) or '__pycache__' in str(py_file):
            continue

        if fix_imports_in_file(py_file):
            print(f"Fixed: {py_file}")
            fixed += 1

    print(f"\nTotal files fixed: {fixed}")


if __name__ == '__main__':
    main()
