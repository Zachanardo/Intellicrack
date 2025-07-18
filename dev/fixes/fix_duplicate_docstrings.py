#!/usr/bin/env python3
"""Fix duplicate and malformed docstrings."""

import re
from pathlib import Path

def fix_duplicate_docstrings(file_path):
    """Fix duplicate docstrings and syntax errors."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix pattern: """Initialize the object.""" followed by proper docstring
        pattern1 = r'(\s+)def __init__\([^)]*\):\s*\n(\s+)"""Initialize the object\."""\s*\n(\s+)("""[^"]+""")'
        
        def fix_duplicate(match):
            indent1 = match.group(1)
            indent2 = match.group(2)
            proper_docstring = match.group(4)
            return f'{indent1}def __init__({match.group(0).split("(", 1)[1].split("):", 1)[0]}):\n{indent2}{proper_docstring}'
        
        content = re.sub(pattern1, fix_duplicate, content, flags=re.DOTALL)
        
        # Fix wrong indentation pattern
        pattern2 = r'(\s+)def __init__\([^)]*\):\s*\n(\s+)"""Initialize the object\."""\s*\n(\s+)("""[^"]*""")'
        content = re.sub(pattern2, fix_duplicate, content, flags=re.DOTALL)
        
        # Fix simple case where there's wrong indentation
        pattern3 = r'(\s+)def __init__\([^)]*\):\s*\n(\s+)"""Initialize the object\."""\s*\n(\s+)("""[^"]*""")'
        content = re.sub(pattern3, fix_duplicate, content, flags=re.DOTALL)
        
        # Remove lines that are just """Initialize the object.""" with wrong indentation
        lines = content.split('\n')
        new_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            # Check if this is a problematic line
            if '"""Initialize the object."""' in line and i > 0:
                prev_line = lines[i-1]
                if 'def __init__' in prev_line:
                    # Skip this line and check if next line has proper docstring
                    if i + 1 < len(lines) and '"""' in lines[i+1]:
                        i += 1  # Skip the problematic line
                        continue
            new_lines.append(line)
            i += 1
        
        content = '\n'.join(new_lines)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed duplicate docstrings in {file_path.relative_to(Path('C:/Intellicrack'))}")
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

# Get all Python files that might have issues
base_path = Path("C:/Intellicrack/intellicrack")

# Focus on files that were processed by the previous script
for py_file in base_path.rglob("*.py"):
    if py_file.name != "__init__.py":
        fix_duplicate_docstrings(py_file)

print("Done fixing duplicate docstrings!")