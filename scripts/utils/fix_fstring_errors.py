#!/usr/bin/env python3
"""Fix f-string double brace errors in plugin_manager_dialog.py"""

import re

def fix_fstring_errors(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find all f-strings and fix double braces
    # Pattern matches f"..." and f'...' strings
    def fix_braces(match):
        quote_char = match.group(1)
        string_content = match.group(2)
        # Replace {{variable}} with {variable} but keep literal {{ and }} 
        # Only fix cases where there's a variable name between braces
        fixed = re.sub(r'\{\{([a-zA-Z_][a-zA-Z0-9_.\[\]\'\"]*)\}\}', r'{\1}', string_content)
        return f'f{quote_char}{fixed}{quote_char}'
    
    # Match f-strings (both single and double quotes)
    content = re.sub(r'f(["\'])(.*?)\1', fix_braces, content, flags=re.DOTALL)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed f-string errors in {file_path}")

if __name__ == "__main__":
    fix_fstring_errors("C:/Intellicrack/intellicrack/ui/dialogs/plugin_manager_dialog.py")