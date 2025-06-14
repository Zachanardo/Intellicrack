#!/usr/bin/env python3
"""
Script to find and fix multi-line f-strings in main_app.py
"""

import re
import os

def fix_multiline_fstrings(file_path):
    """Find and fix multi-line f-strings in the given file."""
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    fixed_lines = []
    i = 0
    fixes_made = []
    
    while i < len(lines):
        line = lines[i]
        
        # Check if this line starts an f-string that might be multi-line
        if 'f"' in line or "f'" in line:
            # Check if the f-string is incomplete (has opening brace but no closing on same line)
            if ('{' in line and 
                line.count('{') > line.count('}') and 
                (('f"' in line and '"' in line and line.rindex('"') < line.rindex('{')) or
                 ("f'" in line and "'" in line and line.rindex("'") < line.rindex('{')))):
                
                # This might be a multi-line f-string
                start_line = i
                combined_line = line.rstrip()
                quote_char = '"' if 'f"' in line else "'"
                
                # Look for the closing quote
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].strip()
                    combined_line += ' ' + next_line
                    
                    # Check if we found the closing quote
                    if quote_char in next_line:
                        # Found potential end of f-string
                        # Make sure it's not escaped
                        if not next_line.endswith('\\' + quote_char):
                            # Fix: combine all lines into one
                            indent = len(line) - len(line.lstrip())
                            fixed_line = ' ' * indent + combined_line + '\n'
                            fixed_lines.append(fixed_line)
                            
                            fixes_made.append({
                                'line': start_line + 1,
                                'original': ''.join(lines[start_line:j+1]),
                                'fixed': fixed_line
                            })
                            
                            i = j + 1
                            break
                    j += 1
                else:
                    # Couldn't find closing quote, keep original
                    fixed_lines.append(line)
                    i += 1
            else:
                fixed_lines.append(line)
                i += 1
        else:
            fixed_lines.append(line)
            i += 1
    
    if fixes_made:
        # Write the fixed content back
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(fixed_lines)
        
        print(f"Fixed {len(fixes_made)} multi-line f-strings in {file_path}")
        for fix in fixes_made:
            print(f"\nLine {fix['line']}:")
            print(f"Original:\n{fix['original']}")
            print(f"Fixed:\n{fix['fixed']}")
    else:
        print(f"No multi-line f-strings found in {file_path}")


if __name__ == "__main__":
    main_app_path = "/mnt/c/Intellicrack/intellicrack/ui/main_app.py"
    fix_multiline_fstrings(main_app_path)