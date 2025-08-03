#!/usr/bin/env python3
"""Final fix for f-string syntax errors in plugin_manager_dialog.py"""

import re

def final_fix_fstring_errors(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix empty f-string expressions like f"{}" 
    content = re.sub(r'f"[^"]*\{\s*\}[^"]*"', lambda m: m.group(0).replace('{}', ''), content)
    content = re.sub(r"f'[^']*\{\s*\}[^']*'", lambda m: m.group(0).replace('{}', ''), content)
    
    # Fix any remaining problematic f-string patterns
    # Look for f-strings that might have template placeholders
    content = re.sub(r'f"([^"]*)\{([^}]*)\}([^"]*)"', r'f"\1{\2}\3"', content)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Applied final f-string fixes to {file_path}")

if __name__ == "__main__":
    final_fix_fstring_errors("C:/Intellicrack/intellicrack/ui/dialogs/plugin_manager_dialog.py")