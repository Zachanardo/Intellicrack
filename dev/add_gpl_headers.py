#!/usr/bin/env python3
"""
Script to add GPL-3.0 headers to all Python files in Intellicrack.
Copyright (C) 2025 Zachary Flint
"""

import os
import sys

GPL_HEADER = '''"""
{description}

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

'''

def extract_module_description(content):
    """Extract the first docstring from the file as module description."""
    lines = content.split('\n')
    in_docstring = False
    docstring_lines = []
    quote_type = None
    
    for i, line in enumerate(lines):
        if not in_docstring:
            if line.strip().startswith('"""') or line.strip().startswith("'''"):
                in_docstring = True
                quote_type = '"""' if line.strip().startswith('"""') else "'''"
                # Check if it's a single-line docstring
                if line.count(quote_type) >= 2:
                    return line.strip().strip(quote_type)
                else:
                    first_line = line.strip()[3:]
                    if first_line:
                        docstring_lines.append(first_line)
        else:
            if quote_type in line:
                last_line = line.strip().replace(quote_type, '')
                if last_line:
                    docstring_lines.append(last_line)
                break
            else:
                docstring_lines.append(line.strip())
    
    if docstring_lines:
        return ' '.join(docstring_lines[:2])  # Take first 2 lines max
    return "Module"  # Default fallback description

def add_gpl_header(file_path):
    """Add GPL header to a Python file."""
    # Skip files that already have the copyright
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    if 'Copyright (C) 2025 Zachary Flint' in content:
        print(f"Skipping {file_path} - already has GPL header")
        return False
    
    # Extract module description from existing docstring or use filename
    description = extract_module_description(content)
    
    # Remove existing docstring if it exists (we'll incorporate it into GPL header)
    lines = content.split('\n')
    new_lines = []
    skip_until = -1
    
    for i, line in enumerate(lines):
        if i <= skip_until:
            continue
            
        if i == 0 and (line.strip().startswith('"""') or line.strip().startswith("'''")):
            # Find the end of the docstring
            quote_type = '"""' if line.strip().startswith('"""') else "'''"
            if line.count(quote_type) >= 2:
                # Single line docstring
                skip_until = i
            else:
                # Multi-line docstring
                for j in range(i + 1, len(lines)):
                    if quote_type in lines[j]:
                        skip_until = j
                        break
        else:
            new_lines.append(line)
    
    # Add GPL header with the description
    new_content = GPL_HEADER.format(description=description) + '\n'.join(new_lines)
    
    # Write the file back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"Added GPL header to {file_path}")
    return True

def process_directory(directory):
    """Process all Python files in a directory recursively."""
    count = 0
    for root, dirs, files in os.walk(directory):
        # Skip __pycache__ directories
        if '__pycache__' in root:
            continue
            
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                if add_gpl_header(file_path):
                    count += 1
    
    return count

if __name__ == '__main__':
    # Process main intellicrack package
    intellicrack_dir = '/mnt/c/Intellicrack/intellicrack'
    scripts_dir = '/mnt/c/Intellicrack/scripts'
    
    print("Adding GPL headers to Intellicrack source files...")
    print("=" * 60)
    
    # Process intellicrack package
    count = process_directory(intellicrack_dir)
    
    # Process scripts directory
    count += process_directory(scripts_dir)
    
    print("=" * 60)
    print(f"Total files updated: {count}")