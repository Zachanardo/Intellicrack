#!/usr/bin/env python3
"""Fix S110 violations (exceptions without logger) in the codebase."""

import re
import sys
from pathlib import Path
from typing import List, Tuple


def has_logger_import(lines: List[str]) -> Tuple[bool, str]:
    """Check if file has logger import and return the logger name."""
    for line in lines[:50]:  # Check first 50 lines
        if 'from intellicrack.logger import logger' in line:
            return True, 'logger'
        if 'self.logger' in line:
            return True, 'self.logger'
        if re.match(r'^logger\s*=', line.strip()):
            return True, 'logger'
    return False, ''

def get_logger_for_context(lines: List[str], line_num: int) -> str:
    """Determine the appropriate logger based on context."""
    # Check if we're in a class method
    for i in range(max(0, line_num - 20), line_num):
        if i < len(lines):
            line = lines[i]
            if re.match(r'^\s*def\s+\w+\s*\(self', line):
                return 'self.logger'
            if re.match(r'^\s*class\s+\w+', line):
                # We're in a class, likely need self.logger
                return 'self.logger'

    # Default to module logger
    return 'logger'

def fix_exception_blocks(file_path: Path) -> Tuple[bool, int]:
    """Fix exception blocks without logger calls."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except:
        return False, 0

    original_lines = lines.copy()
    fixes_made = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check if this is an except block
        match = re.match(r'^(\s*)except\s+(.+?):\s*$', line)
        if match:
            indent = match.group(1)
            exception_info = match.group(2)

            # Parse exception type and variable
            if ' as ' in exception_info:
                exception_type, exception_var = exception_info.split(' as ', 1)
                exception_var = exception_var.strip()
            else:
                exception_type = exception_info
                exception_var = 'e'
                # Update the except line to include 'as e'
                lines[i] = f"{indent}except {exception_type} as {exception_var}:\n"

            # Check if next lines have logger
            has_logger = False
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                next_stripped = next_line.strip()
                next_indent = len(next_line) - len(next_line.lstrip())

                # If we've left the except block
                if next_stripped and next_indent <= len(indent):
                    break

                if 'logger' in next_line or 'logging' in next_line:
                    has_logger = True
                    break
                j += 1

            if not has_logger:
                # Determine the appropriate logger
                logger_name = get_logger_for_context(lines, i)

                # Determine appropriate message based on exception type
                if exception_type == 'ImportError':
                    message = f"Import error in {file_path.name}"
                elif exception_type == 'FileNotFoundError':
                    message = f"File not found in {file_path.name}"
                elif exception_type == 'KeyError':
                    message = f"Key error in {file_path.name}"
                elif exception_type == 'ValueError':
                    message = f"Value error in {file_path.name}"
                elif exception_type == 'TypeError':
                    message = f"Type error in {file_path.name}"
                elif exception_type == 'AttributeError':
                    message = f"Attribute error in {file_path.name}"
                elif exception_type in ['Exception', 'BaseException']:
                    message = f"Error in {file_path.name}"
                else:
                    message = f"{exception_type} in {file_path.name}"

                # Insert logger line
                logger_line = f"{indent}    {logger_name}.error(\"{message}: %s\", {exception_var})\n"

                # Find where to insert the logger line
                insert_pos = i + 1
                if insert_pos < len(lines) and lines[insert_pos].strip() == '':
                    # If next line is empty, replace it
                    lines[insert_pos] = logger_line
                else:
                    lines.insert(insert_pos, logger_line)

                fixes_made += 1

        i += 1

    # Check if we need to add logger import
    if fixes_made > 0:
        has_import, _ = has_logger_import(lines)
        if not has_import:
            # Add logger import at the top
            import_added = False
            for i, line in enumerate(lines):
                if line.strip() and not line.startswith('#'):
                    lines.insert(i, 'from intellicrack.logger import logger\n')
                    import_added = True
                    break

            if not import_added:
                lines.insert(0, 'from intellicrack.logger import logger\n')

    # Write back if changes were made
    if lines != original_lines:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return True, fixes_made

    return False, 0

def main():
    """Main function to fix S110 violations."""
    if len(sys.argv) > 1:
        # Fix specific file
        file_path = Path(sys.argv[1])
        if file_path.exists():
            fixed, count = fix_exception_blocks(file_path)
            if fixed:
                print(f"Fixed {count} violations in {file_path}")
            else:
                print(f"No violations found in {file_path}")
        else:
            print(f"File not found: {file_path}")
    else:
        # Fix all files with most violations first
        files_to_fix = [
            'intellicrack/ui/main_app.py',
            'intellicrack/scripts/cli/interactive_mode.py',
            'intellicrack/core/c2/c2_client.py',
            'intellicrack/core/exploitation/privilege_escalation.py',
            'intellicrack/core/exploitation/lateral_movement.py',
        ]

        project_root = Path('/mnt/c/Intellicrack')

        for file_rel_path in files_to_fix:
            file_path = project_root / file_rel_path
            if file_path.exists():
                print(f"\nProcessing {file_path}...")
                fixed, count = fix_exception_blocks(file_path)
                if fixed:
                    print(f"  Fixed {count} violations")
                else:
                    print("  No violations found")
            else:
                print(f"\nFile not found: {file_path}")

if __name__ == "__main__":
    main()
