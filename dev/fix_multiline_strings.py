#!/usr/bin/env python3
"""
Fix multi-line string literals in logging calls.
"""

import re
import os

def fix_multiline_strings_in_file(filepath):
    """Fix unterminated string literals from logging conversions."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to find logging calls with newlines in the format string
        # This happens when the script converted multi-line f-strings
        pattern = r'(logger\.[a-z]+\(".*?)\n(%s")'
        
        # Replace newlines within logging format strings with \n
        fixed_content = re.sub(pattern, r'\1\\n\2', content, flags=re.MULTILINE | re.DOTALL)
        
        # Also fix self.logger patterns
        pattern2 = r'(self\.logger\.[a-z]+\(".*?)\n(%s")'
        fixed_content = re.sub(pattern2, r'\1\\n\2', fixed_content, flags=re.MULTILINE | re.DOTALL)
        
        if fixed_content != content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"Fixed: {filepath}")
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Find and fix all Python files with multi-line string issues."""
    fixed_count = 0
    
    for root, dirs, files in os.walk('/mnt/c/Intellicrack/intellicrack'):
        if '__pycache__' in root:
            continue
            
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                if fix_multiline_strings_in_file(filepath):
                    fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()