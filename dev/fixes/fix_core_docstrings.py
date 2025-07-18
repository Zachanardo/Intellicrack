#!/usr/bin/env python3
"""Fix docstrings in core directories."""

import re
from pathlib import Path

def fix_simple_init_docstrings(file_path):
    """Fix simple __init__ methods without docstrings."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Pattern: def __init__(params): followed by non-docstring line
        pattern = r'(\s+)def __init__\([^)]*\):\s*\n(\s+)(?!""")([^\n]*)'
        
        def add_docstring(match):
            method_indent = match.group(1)
            body_indent = match.group(2)
            first_line = match.group(3)
            
            # Add simple docstring
            docstring = f'{body_indent}"""Initialize the object."""\n'
            
            return f'{method_indent}def __init__({match.group(0).split("(", 1)[1].split("):", 1)[0]}):\n{docstring}{body_indent}{first_line}'
        
        new_content = re.sub(pattern, add_docstring, content)
        
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed simple docstrings in {file_path.relative_to(Path('C:/Intellicrack'))}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Process key directories
base_path = Path("C:/Intellicrack/intellicrack")

directories_to_process = [
    "core",
    "ui", 
    "scripts",
    "protection",
    "tools",
    "llm",
    "tests"
]

total_fixed = 0

for dir_name in directories_to_process:
    dir_path = base_path / dir_name
    if dir_path.exists():
        print(f"\nProcessing {dir_name} directory...")
        for py_file in dir_path.rglob("*.py"):
            if fix_simple_init_docstrings(py_file):
                total_fixed += 1

# Also process root level Python files
for py_file in base_path.glob("*.py"):
    if fix_simple_init_docstrings(py_file):
        total_fixed += 1

print(f"\nTotal files fixed: {total_fixed}")