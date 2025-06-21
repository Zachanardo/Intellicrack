#!/usr/bin/env python3
"""
Comprehensive whitespace fixer for Python files.
Fixes trailing whitespace AND whitespace-only blank lines.
"""

import os

def fix_all_whitespace(file_path):
    """Fix all whitespace issues in a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        lines = content.splitlines(keepends=True)
        fixed_lines = []
        
        for line in lines:
            # Remove ALL trailing whitespace from every line
            # This includes both regular lines and blank lines
            if line.endswith('\n'):
                fixed_line = line.rstrip() + '\n'
            elif line.endswith('\r\n'):
                fixed_line = line.rstrip() + '\r\n'
            else:
                fixed_line = line.rstrip()
            fixed_lines.append(fixed_line)
        
        fixed_content = ''.join(fixed_lines)
        
        # Only write if something actually changed
        if fixed_content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f'Fixed all whitespace in: {file_path}')
            return True
        return False
    except Exception as e:
        print(f'Error processing {file_path}: {e}')
        return False

def main():
    """Main function to process all Python files"""
    fixed_count = 0
    processed_count = 0
    
    # Find all Python files in intellicrack directory
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                processed_count += 1
                if fix_all_whitespace(file_path):
                    fixed_count += 1
    
    print(f'Processed {processed_count} Python files')
    print(f'Fixed comprehensive whitespace in {fixed_count} files')

if __name__ == '__main__':
    main()