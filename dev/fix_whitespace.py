#!/usr/bin/env python3
"""Fix W293 errors - remove whitespace from blank lines"""

import os
import re

def fix_blank_line_whitespace(file_path):
    """Remove whitespace from blank lines in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Replace lines that contain only whitespace with empty lines
        fixed_content = re.sub(r'^[ \t]+$', '', content, flags=re.MULTILINE)

        if content != fixed_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"Fixed: {file_path}")
            return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

    return False

def main():
    """Fix W293 errors in all Python files"""
    fixed_count = 0

    for root, dirs, files in os.walk('.'):
        # Skip certain directories
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', '.pytest_cache', 'node_modules', 'venv'}]

        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                if fix_blank_line_whitespace(file_path):
                    fixed_count += 1

    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()