#!/usr/bin/env python3
"""Fix docstrings in plugins directory."""

import re
from pathlib import Path

def add_init_docstring_after_class(file_path):
    """Add __init__ docstrings to classes that don't have them."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern to find class with docstring followed by __init__ without docstring
        pattern = r'(class\s+\w+[^:]*:\s*\n\s*"""[^"]*"""\s*\n\s*)(def __init__\([^)]*\):\s*\n)(\s*)([^\n]*\n)'
        
        def add_docstring(match):
            class_part = match.group(1)
            init_def = match.group(2)
            indent = match.group(3)
            first_line = match.group(4)
            
            # Check if already has docstring
            if '"""' in first_line:
                return match.group(0)
            
            # Add generic docstring
            docstring = f'{indent}"""Initialize the object."""\n'
            return class_part + init_def + docstring + indent + first_line
        
        new_content = re.sub(pattern, add_docstring, content)
        
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed docstrings in {file_path}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Find all Python files in plugins directory
base_path = Path("C:/Intellicrack")
plugins_dir = base_path / "intellicrack" / "plugins"

if plugins_dir.exists():
    for py_file in plugins_dir.rglob("*.py"):
        if py_file.name != "__init__.py":
            print(f"Processing {py_file.relative_to(base_path)}...")
            add_init_docstring_after_class(py_file)

print("Done processing plugins docstrings!")