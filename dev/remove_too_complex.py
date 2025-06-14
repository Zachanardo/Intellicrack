#!/usr/bin/env python3
"""
Script to remove all instances of '# pylint: disable=too-complex' from Python files.
"""

import os
import re
from pathlib import Path


def remove_too_complex_comments(file_path):
    """
    Remove '# pylint: disable=too-complex' comments from a file.
    
    Returns True if the file was modified, False otherwise.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return False
    
    modified = False
    new_lines = []
    
    for line in lines:
        original_line = line
        
        # Check if line contains only the comment (with optional whitespace)
        if line.strip() == '# pylint: disable=too-complex':
            # Skip this line entirely
            modified = True
            continue
        
        # Check if line contains the comment at the end
        if '# pylint: disable=too-complex' in line:
            # Remove the comment from the line
            line = line.replace('# pylint: disable=too-complex', '')
            # Remove trailing whitespace
            line = line.rstrip() + '\n' if line.strip() else ''
            if line != original_line:
                modified = True
        
        new_lines.append(line)
    
    if modified:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            return True
        except Exception as e:
            print(f"Error writing {file_path}: {e}")
            return False
    
    return False


def main():
    """Main function to process all Python files."""
    intellicrack_dir = Path(__file__).parent.parent / 'intellicrack'
    
    if not intellicrack_dir.exists():
        print(f"Error: Directory {intellicrack_dir} does not exist")
        return
    
    print(f"Scanning for Python files in: {intellicrack_dir}")
    
    modified_files = []
    total_files = 0
    
    # Find all .py files recursively
    for py_file in intellicrack_dir.rglob('*.py'):
        total_files += 1
        if remove_too_complex_comments(py_file):
            modified_files.append(py_file)
            print(f"Modified: {py_file.relative_to(intellicrack_dir.parent)}")
    
    # Print summary
    print("\n" + "="*60)
    print(f"Total Python files scanned: {total_files}")
    print(f"Files modified: {len(modified_files)}")
    
    if modified_files:
        print("\nModified files:")
        for f in modified_files:
            print(f"  - {f.relative_to(intellicrack_dir.parent)}")
    else:
        print("\nNo files were modified (no '# pylint: disable=too-complex' comments found)")


if __name__ == "__main__":
    main()