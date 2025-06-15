#!/usr/bin/env python3
"""
Fix collection type initializations after W0201 fixes.
"""

import re

# Attributes that should be initialized as collections instead of None
COLLECTION_FIXES = {
    'intellicrack/ui/main_app.py': {
        '_hex_viewer_dialogs': '[]',  # Used as a list
        'reports': '[]',  # Likely used as a list
        'log_access_history': '[]',  # Likely used as a list
        'ai_conversation_history': '[]',  # Likely used as a list
    }
}


def fix_collection_initializations(file_path: str, fixes: dict):
    """Fix collection initializations."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        
        # Find __init__ methods and fix initializations
        in_init = False
        init_indent = 0
        
        for i, line in enumerate(lines):
            # Check if we're in an __init__ method
            if re.match(r'^\s+def __init__\(', line):
                in_init = True
                init_indent = len(line) - len(line.lstrip())
                continue
            
            # Check if we've left the __init__ method
            if in_init and line.strip() and not line.startswith(' ' * (init_indent + 4)):
                in_init = False
            
            # Fix collection initializations
            if in_init:
                for attr_name, init_value in fixes.items():
                    pattern = f'^(\\s+)self\\.{attr_name}\\s*=\\s*None\\s*$'
                    match = re.match(pattern, line)
                    if match:
                        indent = match.group(1)
                        lines[i] = f'{indent}self.{attr_name} = {init_value}\n'
                        print(f"  Fixed: self.{attr_name} = None -> self.{attr_name} = {init_value}")
                        modified = True
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"  Saved changes to {file_path}")
        else:
            print(f"  No collection initialization fixes needed")
            
    except Exception as e:
        print(f"  Error processing {file_path}: {e}")


def main():
    """Main function to fix collection initializations."""
    import os
    
    print("Fixing collection type initializations...\n")
    
    for file_path, fixes in COLLECTION_FIXES.items():
        full_path = os.path.join('/mnt/c/Intellicrack', file_path)
        
        if os.path.exists(full_path):
            print(f"Processing {file_path}...")
            fix_collection_initializations(full_path, fixes)
        else:
            print(f"File not found: {full_path}")
    
    print("\nDone! Collection types are now properly initialized.")


if __name__ == '__main__':
    main()