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

"""Script to fix E402 import order issues."""

import ast
import re
from pathlib import Path
from typing import List, Tuple


def extract_docstring_and_imports(content: str) -> Tuple[str, List[str], List[str], str]:
    """Extract docstring, imports, and rest of the code."""
    lines = content.split('\n')

    # Find docstring
    docstring_lines = []
    import_lines = []
    other_lines = []

    i = 0
    # Skip shebang if present
    if lines and lines[0].startswith('#!'):
        other_lines.append(lines[0])
        i = 1

    # Skip encoding declaration if present
    if i < len(lines) and (lines[i].startswith('# -*- coding:') or lines[i].startswith('# coding:')):
        other_lines.append(lines[i])
        i += 1

    # Find docstring
    in_docstring = False
    docstring_quote = None
    docstring_start = -1

    for j in range(i, len(lines)):
        line = lines[j].strip()

        # Check for docstring start
        if not in_docstring and (line.startswith('"""') or line.startswith("'''")):
            in_docstring = True
            docstring_quote = '"""' if line.startswith('"""') else "'''"
            docstring_start = j

            # Check if it's a single-line docstring
            if line.count(docstring_quote) >= 2:
                docstring_lines = lines[docstring_start:j+1]
                i = j + 1
                break
        elif in_docstring and docstring_quote in line:
            # End of multi-line docstring
            docstring_lines = lines[docstring_start:j+1]
            i = j + 1
            break

    # Now collect all imports and other code
    for j in range(i, len(lines)):
        line = lines[j]
        stripped = line.strip()

        # Check if it's an import statement
        if (stripped.startswith('import ') or
            stripped.startswith('from ') or
                (j > 0 and lines[j-1].strip().endswith('\\'))):  # Continuation of import
            import_lines.append(line)
        elif stripped == '' and j < len(lines) - 1:
            # Empty line - check if more imports follow
            temp_j = j + 1
            while temp_j < len(lines) and lines[temp_j].strip() == '':
                temp_j += 1
            if temp_j < len(lines):
                next_line = lines[temp_j].strip()
                if next_line.startswith('import ') or next_line.startswith('from '):
                    # Keep empty line between imports
                    import_lines.append(line)
                else:
                    other_lines.extend(lines[j:])
                    break
            else:
                other_lines.extend(lines[j:])
                break
        else:
            # Not an import, so everything else goes to other_lines
            other_lines.extend(lines[j:])
            break

    return '\n'.join(docstring_lines), import_lines, other_lines[:-1] if other_lines and other_lines[-1] == '' else other_lines, '\n'.join(lines)


def fix_e402_in_file(filepath: Path) -> bool:
    """Fix E402 issues in a single file."""
    try:
        content = filepath.read_text(encoding='utf-8')

        # Extract components
        docstring, imports, rest, original = extract_docstring_and_imports(
            content)

        # Build the fixed content
        fixed_parts = []

        # Add docstring if present
        if docstring:
            fixed_parts.append(docstring)
            fixed_parts.append('')  # Empty line after docstring

        # Add all imports
        if imports:
            # Remove empty lines at the end of imports
            while imports and imports[-1].strip() == '':
                imports.pop()
            fixed_parts.extend(imports)
            fixed_parts.append('')  # Empty line after imports

        # Add the rest
        if rest:
            # Remove leading empty lines from rest
            while rest and rest[0].strip() == '':
                rest.pop(0)
            fixed_parts.extend(rest)

        # Join everything
        fixed_content = '\n'.join(fixed_parts)

        # Only write if changed
        if fixed_content != original:
            filepath.write_text(fixed_content, encoding='utf-8')
            return True
        return False

    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False


def main():
    """Main function to fix E402 in all Python files."""
    intellicrack_dir = Path('/mnt/c/Intellicrack/intellicrack')

    fixed_count = 0
    error_count = 0

    for py_file in intellicrack_dir.rglob('*.py'):
        if 'venv' in str(py_file) or '__pycache__' in str(py_file):
            continue

        print(f"Processing {py_file}...")
        if fix_e402_in_file(py_file):
            fixed_count += 1
            print(f"  Fixed!")
        else:
            print(f"  No changes needed")

    print(f"\nFixed {fixed_count} files")
    if error_count:
        print(f"Errors in {error_count} files")


if __name__ == '__main__':
    main()
