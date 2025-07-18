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
import re
import ast

def find_qlineedit_issues(directory):
    """Find QLineEdit widgets that incorrectly use toPlainText()"""
    issues = []

    for root, dirs, files in os.walk(directory):
        # Skip __pycache__ and .git directories
        dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.pytest_cache']]

        for file in files:
            if not file.endswith('.py'):
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')

                # Find QLineEdit declarations
                qlineedit_vars = set()
                for i, line in enumerate(lines):
                    # Match patterns like: self.var = QLineEdit()
                    match = re.search(r'self\.(\w+)\s*=\s*QLineEdit\s*\(', line)
                    if match:
                        qlineedit_vars.add(match.group(1))
                    # Also match: var = QLineEdit()
                    match = re.search(r'^(\s*)(\w+)\s*=\s*QLineEdit\s*\(', line)
                    if match:
                        qlineedit_vars.add(match.group(2))

                # Now find uses of toPlainText() on these variables
                for i, line in enumerate(lines):
                    for var in qlineedit_vars:
                        # Check for self.var.toPlainText()
                        if f'self.{var}.toPlainText()' in line:
                            issues.append({
                                'file': filepath,
                                'line': i + 1,
                                'var': var,
                                'code': line.strip()
                            })
                        # Check for var.toPlainText()
                        elif f'{var}.toPlainText()' in line and not f'self.{var}' in line:
                            issues.append({
                                'file': filepath,
                                'line': i + 1,
                                'var': var,
                                'code': line.strip()
                            })

            except Exception as e:
                print(f"Error reading {filepath}: {e}")

    return issues

if __name__ == "__main__":
    issues = find_qlineedit_issues("intellicrack")

    if issues:
        print(f"Found {len(issues)} QLineEdit.toPlainText() errors:\n")
        for issue in issues:
            print(f"{issue['file']}:{issue['line']}")
            print(f"  Variable: {issue['var']}")
            print(f"  Code: {issue['code']}")
            print()
    else:
        print("No QLineEdit.toPlainText() errors found!")
