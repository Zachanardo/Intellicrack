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

"""Fix all S110 violations (exceptions without logger) in the codebase."""

import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

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

def get_appropriate_message(exception_type: str, file_name: str) -> str:
    """Get appropriate error message based on exception type."""
    base_name = os.path.basename(file_name).replace('.py', '')

    messages = {
        'ImportError': f"Import error in {base_name}",
        'FileNotFoundError': f"File not found in {base_name}",
        'KeyError': f"Key error in {base_name}",
        'ValueError': f"Value error in {base_name}",
        'TypeError': f"Type error in {base_name}",
        'AttributeError': f"Attribute error in {base_name}",
        'IndexError': f"Index error in {base_name}",
        'ZeroDivisionError': f"Division by zero in {base_name}",
        'NameError': f"Name error in {base_name}",
        'RuntimeError': f"Runtime error in {base_name}",
        'OSError': f"OS error in {base_name}",
        'IOError': f"IO error in {base_name}",
        'PermissionError': f"Permission error in {base_name}",
        'ConnectionError': f"Connection error in {base_name}",
        'TimeoutError': f"Timeout error in {base_name}",
        'JSONDecodeError': f"JSON decode error in {base_name}",
        'subprocess.CalledProcessError': f"Subprocess error in {base_name}",
        'subprocess.TimeoutExpired': f"Subprocess timeout in {base_name}",
        'socket.error': f"Socket error in {base_name}",
        'psutil.NoSuchProcess': f"No such process in {base_name}",
        'psutil.AccessDenied': f"Access denied in {base_name}",
    }

    # Handle composite exceptions
    if ',' in exception_type:
        return f"Error in {base_name}"

    # Extract base exception type
    base_exception = exception_type.split()[0].strip('()')

    return messages.get(base_exception, f"{base_exception} in {base_name}")

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

        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

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

                # Get appropriate message
                message = get_appropriate_message(exception_type, str(file_path))

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
            # Add logger import at the top after other imports
            import_added = False
            for i, line in enumerate(lines):
                if line.strip() and not line.startswith('#') and not line.startswith('from') and not line.startswith('import'):
                    # Insert before first non-import line
                    lines.insert(i, 'from intellicrack.logger import logger\n\n')
                    import_added = True
                    break

            if not import_added:
                # If no suitable place found, add at the beginning
                lines.insert(0, 'from intellicrack.logger import logger\n\n')

    # Write back if changes were made
    if lines != original_lines:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return True, fixes_made

    return False, 0

def process_file(file_path: Path) -> Dict[str, any]:
    """Process a single file and return results."""
    try:
        fixed, count = fix_exception_blocks(file_path)
        return {
            'path': str(file_path),
            'fixed': fixed,
            'count': count,
            'error': None
        }
    except Exception as e:
        return {
            'path': str(file_path),
            'fixed': False,
            'count': 0,
            'error': str(e)
        }

def find_files_with_exceptions(root_dir: Path) -> List[Path]:
    """Find all Python files that contain exception handling."""
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.py'):
                file_path = Path(root) / filename
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'except' in content:
                            files.append(file_path)
                except Exception as e:
                    logger.debug(f"Failed to check file {file_path}: {e}")
    return files

def main():
    """Main function to fix all S110 violations."""
    project_root = Path('/mnt/c/Intellicrack')
    intellicrack_dir = project_root / 'intellicrack'

    print("Finding files with exception handling...")
    files_to_process = find_files_with_exceptions(intellicrack_dir)
    print(f"Found {len(files_to_process)} files to process")

    # Process files in parallel for speed
    total_fixed = 0
    total_violations = 0
    errors = []

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_file, file_path): file_path for file_path in files_to_process}

        for future in as_completed(futures):
            result = future.result()
            if result['fixed']:
                total_fixed += 1
                total_violations += result['count']
                print(f"Fixed {result['count']} violations in {result['path']}")
            elif result['error']:
                errors.append(result)

    elapsed_time = time.time() - start_time

    print(f"\n{'='*60}")
    print("SUMMARY:")
    print(f"{'='*60}")
    print(f"Total files processed: {len(files_to_process)}")
    print(f"Files fixed: {total_fixed}")
    print(f"Total violations fixed: {total_violations}")
    print(f"Processing time: {elapsed_time:.2f} seconds")

    if errors:
        print(f"\nErrors encountered in {len(errors)} files:")
        for error in errors[:5]:
            print(f"  {error['path']}: {error['error']}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")

if __name__ == "__main__":
    main()
