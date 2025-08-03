#!/usr/bin/env python3
"""
Fix all exec_() to exec for PyQt6 compatibility
"""
import os
import re

def fix_exec_in_file(filepath):
    """Fix exec_() to exec in a single file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Count occurrences
        count = len(re.findall(r'\.exec_\(\)', content))

        if count > 0:
            # Replace .exec() with .exec()
            new_content = re.sub(r'\.exec_\(\)', '.exec()', content)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)

            print(f"Fixed {count} occurrence(s) in {filepath}")
            return count
        return 0
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return 0

def main():
    """Fix exec_() in all Python files"""
    print("Fixing exec_() to exec for PyQt6 compatibility...")

    total_files = 0
    total_fixes = 0

    for root, dirs, files in os.walk('/mnt/c/Intellicrack'):
        # Skip virtual environments and cache directories
        dirs[:] = [d for d in dirs if d not in ['.venv_wsl', '.venv_windows', '__pycache__', '.git']]

        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                fixes = fix_exec_in_file(filepath)
                if fixes > 0:
                    total_files += 1
                    total_fixes += fixes

    print(f"\nFixed {total_fixes} occurrence(s) in {total_files} file(s)")

if __name__ == "__main__":
    main()
