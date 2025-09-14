#!/usr/bin/env python3
"""Final comprehensive syntax error fix.

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

import re
from pathlib import Path

def fix_indentation_errors(file_path):
    """Fix indentation and syntax errors in Python files."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content
        lines = content.split('\n')
        new_lines = []

        i = 0
        while i < len(lines):
            line = lines[i]

            # Fix common indentation patterns
            if line.strip():
                # If line starts with function/class but is indented wrong
                if re.match(r'^\s{5,}(def |class |@|return |if |for |while |with |try:|except|finally)', line):
                    # Reduce indentation to proper level
                    leading_spaces = len(line) - len(line.lstrip())
                    if leading_spaces > 4:
                        new_line = '    ' + line.lstrip()
                        new_lines.append(new_line)
                    else:
                        new_lines.append(line)
                # Fix lines that should be unindented after docstrings
                elif i > 0 and lines[i-1].strip().endswith('"""'):
                    if line.startswith('    ') and any(keyword in line for keyword in ['self.', 'super()', 'return ', 'import ', 'from ']):
                        new_lines.append(line[4:] if len(line) > 4 else line.lstrip())
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

            i += 1

        content = '\n'.join(new_lines)

        # Fix specific syntax patterns
        content = re.sub(r'^(\s*)def ([^:]+):\s*\n(\s*)"""([^"]+)"""\s*\n(\s*)(return .+)',
                        r'\1def \2:\n\3"""\4"""\n\1    \6', content, flags=re.MULTILINE)

        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed indentation in {file_path.relative_to(Path('C:/Intellicrack'))}")
            return True

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

    return False

# Files with known syntax errors
problematic_files = [
    "intellicrack/config.py",
    "intellicrack/core/ai_model_manager.py"
]

base_path = Path("C:/Intellicrack")

for file_path in problematic_files:
    full_path = base_path / file_path
    if full_path.exists():
        fix_indentation_errors(full_path)

print("Done fixing syntax errors!")
