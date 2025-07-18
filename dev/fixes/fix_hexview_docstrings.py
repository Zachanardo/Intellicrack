#!/usr/bin/env python3
"""Fix all remaining docstrings in hexview module."""

import re
from pathlib import Path

def fix_init_docstring(file_path, class_name="", method_signature=""):
    """Fix __init__ docstring in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to find __init__ methods without docstrings
        pattern = r'(\s*)def __init__\([^)]*\):\s*\n(\s*)(.*?)(?=\n\s*def|\n\s*@|\n\s*class|\Z)'
        
        def replace_init(match):
            indent = match.group(1)
            content_indent = match.group(2) or (indent + '    ')
            method_body = match.group(3)
            
            # Check if already has a docstring
            if '"""' in method_body[:100]:
                return match.group(0)
            
            # Generate docstring based on common patterns
            if 'parent' in method_body:
                docstring = f'{content_indent}"""Initialize the object.\n\n{content_indent}Args:\n{content_indent}    parent: Parent object for proper memory management\n{content_indent}"""\n'
            elif 'config' in method_body:
                docstring = f'{content_indent}"""Initialize with configuration.\n\n{content_indent}Args:\n{content_indent}    config: Configuration object\n{content_indent}"""\n'
            else:
                docstring = f'{content_indent}"""Initialize the object."""\n'
            
            return f'{indent}def __init__({match.group(0).split("(", 1)[1].split("):", 1)[0]}):\n{docstring}{content_indent}{method_body}'
        
        # Apply the replacement
        new_content = re.sub(pattern, replace_init, content, flags=re.DOTALL)
        
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed __init__ docstrings in {file_path}")
            return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

def fix_magic_method_docstrings(file_path):
    """Fix magic method docstrings."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        replacements = [
            (r'(\s*)def __str__\(self\):\s*\n(\s*)return', 
             r'\1def __str__(self):\n\2"""Return string representation."""\n\2return'),
            (r'(\s*)def __repr__\(self\):\s*\n(\s*)return', 
             r'\1def __repr__(self):\n\2"""Return detailed string representation."""\n\2return'),
            (r'(\s*)def __len__\(self\):\s*\n(\s*)return', 
             r'\1def __len__(self):\n\2"""Return length."""\n\2return'),
            (r'(\s*)def __bool__\(self\):\s*\n(\s*)return', 
             r'\1def __bool__(self):\n\2"""Return boolean value."""\n\2return'),
        ]
        
        new_content = content
        for pattern, replacement in replacements:
            new_content = re.sub(pattern, replacement, new_content)
        
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed magic method docstrings in {file_path}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Process hexview files
hexview_files = [
    "intellicrack/hexview/hex_commands.py",
    "intellicrack/hexview/large_file_handler.py", 
    "intellicrack/hexview/performance_monitor.py",
    "intellicrack/ml/pattern_evolution_tracker.py"
]

base_path = Path("C:/Intellicrack")

for file_path in hexview_files:
    full_path = base_path / file_path
    if full_path.exists():
        print(f"Processing {file_path}...")
        fix_init_docstring(full_path)
        fix_magic_method_docstrings(full_path)
    else:
        print(f"File not found: {file_path}")

print("Done processing hexview docstrings!")