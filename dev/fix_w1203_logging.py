#!/usr/bin/env python3
"""Fix W1203 logging-fstring-interpolation errors by converting f-strings to lazy formatting."""

import re
import os
import glob

def fix_logging_fstring(line):
    """Convert f-string logging to lazy % formatting."""
    # Pattern to match logger calls with f-strings
    patterns = [
        (r'(logger\.\w+)\(f"([^"]+)"\)', r'\1("\2")'),  # logger.info(f"...")
        (r'(logger\.\w+)\(f\'([^\']+)\'\)', r'\1("\2")'),  # logger.info(f'...')
        (r'(self\.logger\.\w+)\(f"([^"]+)"\)', r'\1("\2")'),  # self.logger.info(f"...")
        (r'(self\.logger\.\w+)\(f\'([^\']+)\'\)', r'\1("\2")'),  # self.logger.info(f'...')
        (r'(cls\.logger\.\w+)\(f"([^"]+)"\)', r'\1("\2")'),  # cls.logger.info(f"...")
        (r'(cls\.logger\.\w+)\(f\'([^\']+)\'\)', r'\1("\2")'),  # cls.logger.info(f'...')
    ]
    
    modified = False
    for pattern, replacement in patterns:
        if re.search(pattern, line):
            # Extract the f-string content
            match = re.search(pattern, line)
            if match:
                # Find all {var} patterns in the f-string
                f_string_content = match.group(2)
                vars_found = re.findall(r'\{([^}]+)\}', f_string_content)
                
                if vars_found:
                    # Replace {var} with %s
                    new_content = f_string_content
                    for var in vars_found:
                        new_content = new_content.replace(f'{{{var}}}', '%s')
                    
                    # Build the new line
                    logger_call = match.group(1)
                    vars_str = ', '.join(vars_found)
                    new_line = re.sub(pattern, f'{logger_call}("{new_content}", {vars_str})', line)
                    return new_line, True
            
            line = re.sub(pattern, replacement, line)
            modified = True
    
    return line, modified

def fix_file(filepath):
    """Fix all W1203 errors in a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        new_lines = []
        
        for line in lines:
            new_line, line_modified = fix_logging_fstring(line)
            new_lines.append(new_line)
            if line_modified:
                modified = True
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
            return True
        
        return False
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Main function."""
    # Find all Python files in intellicrack
    python_files = glob.glob('/mnt/c/Intellicrack/intellicrack/**/*.py', recursive=True)
    
    fixed_count = 0
    for filepath in python_files:
        if fix_file(filepath):
            fixed_count += 1
            print(f"Fixed: {filepath}")
    
    print(f"\nFixed {fixed_count} files with W1203 errors!")

if __name__ == '__main__':
    main()