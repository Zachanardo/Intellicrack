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
Fix W1203 logging-fstring-interpolation warnings.
Convert f-strings in logging to lazy % formatting.
This script is conservative and only fixes simple cases.
"""

import os
import re
import sys
from datetime import datetime

# Track changes for reporting
changes_made = []
skipped_complex = []


def is_simple_variable(expr):
    """Check if expression is a simple variable (no method calls, attributes, etc.)"""
    # Simple variable: just alphanumeric and underscore
    # Allow simple attributes like obj.attr but not method calls
    return re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)?$', expr.strip())

# pylint: disable=too-complex


def convert_fstring_to_percent(match):
    """Convert f-string logging to % formatting."""
    prefix = match.group(1)  # logger.error
    quote = match.group(2)   # " or '
    content = match.group(3)  # string content

    # Find all {expression} in the f-string
    expressions = []
    new_content = content

    # Pattern to match {expression} including format specs
    pattern = r'\{([^}:]+)(?::([^}]+))?\}'

    for expr_match in re.finditer(pattern, content):
        expr = expr_match.group(1)
        format_spec = expr_match.group(2)

        # Skip complex expressions
        if not is_simple_variable(expr):
            return None  # Signal to skip this one

        expressions.append(expr.strip())

        # Replace with appropriate format specifier
        if format_spec:
            # Handle format specifiers like .2f, >10, etc.
            if 'd' in format_spec or 'x' in format_spec or 'o' in format_spec:
                replacement = '%d'
            elif 'f' in format_spec or 'e' in format_spec or 'g' in format_spec:
                replacement = '%f'
            else:
                replacement = '%s'
        else:
            replacement = '%s'

        # Replace this specific occurrence
        old_pattern = '{' + expr + \
            (':' + format_spec if format_spec else '') + '}'
        new_content = new_content.replace(old_pattern, replacement, 1)

    if expressions:
        # Build the new logging call
        return f'{prefix}({quote}{new_content}{quote}, {", ".join(expressions)})'
    else:
        # No expressions found, just remove the f prefix
        return f'{prefix}({quote}{content}{quote})'


def fix_logging_in_line(line, filename, line_num):
    """Fix logging f-strings in a single line."""
    # Patterns for different logging calls
    patterns = [
        r'((?:self\.)?logger\.(?:debug|info|warning|error|critical))\(f(["\'])([^"\']+)\2\)',
        r'(logging\.(?:debug|info|warning|error|critical))\(f(["\'])([^"\']+)\2\)',
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            result = convert_fstring_to_percent(match)
            if result is None:
                # Complex expression, skip
                skipped_complex.append(
                    f"{filename}:{line_num} - {line.strip()}")
                return line
            else:
                # Track the change
                changes_made.append({
                    'file': filename,
                    'line': line_num,
                    'old': line.strip(),
                    'new': re.sub(pattern, result, line).strip()
                })
                return re.sub(pattern, result, line)

    return line


def process_file(filepath):
    """Process a single file to fix logging f-strings."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        modified = False
        new_lines = []
        filename = os.path.relpath(filepath, '/mnt/c/Intellicrack')

        for i, line in enumerate(lines, 1):
            new_line = fix_logging_in_line(line, filename, i)
            if new_line != line:
                modified = True
            new_lines.append(new_line)

        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False


def write_report():
    """Write a detailed report of changes."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f'/mnt/c/Intellicrack/dev/logging_fixes_report_{timestamp}.txt'

    with open(report_file, 'w') as f:
        f.write("W1203 Logging Format Fixes Report\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Total changes made: {len(changes_made)}\n")
        f.write(f"Complex expressions skipped: {len(skipped_complex)}\n\n")

        if changes_made:
            f.write("CHANGES MADE:\n")
            f.write("-" * 80 + "\n")
            for change in changes_made:
                f.write(f"\nFile: {change['file']} (line {change['line']})\n")
                f.write(f"OLD: {change['old']}\n")
                f.write(f"NEW: {change['new']}\n")

        if skipped_complex:
            f.write("\n\nCOMPLEX EXPRESSIONS SKIPPED (need manual review):\n")
            f.write("-" * 80 + "\n")
            for skip in skipped_complex:
                f.write(f"{skip}\n")

    return report_file


def main():
    """Main function to process Python files."""
    print("Starting W1203 logging format fixes...")
    print("This script will only fix simple variable substitutions.")
    print("Complex expressions will be skipped for manual review.\n")

    # Process all Python files in intellicrack directory
    files_processed = 0
    files_modified = 0

    for root, dirs, files in os.walk('/mnt/c/Intellicrack/intellicrack'):
        # Skip __pycache__ directories
        if '__pycache__' in root:
            continue

        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                files_processed += 1
                if process_file(filepath):
                    files_modified += 1
                    print(
                        f"Modified: {os.path.relpath(filepath, '/mnt/c/Intellicrack')}")

    # Write report
    report_file = write_report()

    print(f"\n{'=' * 60}")
    print(f"Files processed: {files_processed}")
    print(f"Files modified: {files_modified}")
    print(f"Total changes: {len(changes_made)}")
    print(f"Skipped complex: {len(skipped_complex)}")
    print(f"\nDetailed report saved to: {report_file}")
    print("\nTo revert changes if needed: git checkout -- intellicrack/")


if __name__ == "__main__":
    main()
