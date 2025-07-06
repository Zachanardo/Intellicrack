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

"""Find S110 violations (exceptions without logger) in the codebase."""

import os
import re
from collections import defaultdict
from pathlib import Path


def find_exception_blocks(file_path):
    """Find exception blocks without logger calls."""
    violations = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except:
        return violations

    in_except_block = False
    except_start_line = 0
    except_indent = 0
    has_logger = False
    exception_type = ""

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Check if we're entering an except block
        if re.match(r'^except\s+.*:', stripped):
            in_except_block = True
            except_start_line = i + 1
            except_indent = len(line) - len(line.lstrip())
            has_logger = False

            # Extract exception type
            match = re.match(r'^except\s+(\w+(?:\s+as\s+\w+)?)?:', stripped)
            if match and match.group(1):
                exception_type = match.group(1).split()[0]
            else:
                exception_type = "Exception"

        elif in_except_block:
            current_indent = len(line) - len(line.lstrip())

            # Check if we're still in the except block
            if current_indent <= except_indent and stripped:
                # We've left the except block
                if not has_logger:
                    violations.append({
                        'line': except_start_line,
                        'type': exception_type,
                        'context': lines[max(0, except_start_line-2):min(len(lines), except_start_line+3)]
                    })
                in_except_block = False
            elif 'logger' in line or 'logging' in line:
                has_logger = True

    # Check if the last except block had a logger
    if in_except_block and not has_logger:
        violations.append({
            'line': except_start_line,
            'type': exception_type,
            'context': lines[max(0, except_start_line-2):min(len(lines), except_start_line+3)]
        })

    return violations

def main():
    """Main function to find all S110 violations."""
    project_root = Path('/mnt/c/Intellicrack')
    intellicrack_dir = project_root / 'intellicrack'

    all_violations = defaultdict(list)

    # Find all Python files
    for root, dirs, files in os.walk(intellicrack_dir):
        for file in files:
            if file.endswith('.py'):
                file_path = Path(root) / file
                violations = find_exception_blocks(file_path)

                if violations:
                    rel_path = file_path.relative_to(project_root)
                    all_violations[str(rel_path)] = violations

    # Print summary
    total_violations = sum(len(v) for v in all_violations.values())
    print(f"Total files with S110 violations: {len(all_violations)}")
    print(f"Total S110 violations: {total_violations}")
    print("\nTop 20 files with most violations:")

    # Sort by number of violations
    sorted_files = sorted(all_violations.items(), key=lambda x: len(x[1]), reverse=True)

    for i, (file_path, violations) in enumerate(sorted_files[:20]):
        print(f"\n{i+1}. {file_path}: {len(violations)} violations")
        for v in violations[:2]:  # Show first 2 violations
            print(f"   Line {v['line']}: except {v['type']}")
            if len(violations) > 2:
                print(f"   ... and {len(violations) - 2} more")
            break

if __name__ == "__main__":
    main()
