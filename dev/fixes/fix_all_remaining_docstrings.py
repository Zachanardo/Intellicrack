#!/usr/bin/env python3
"""Fix all remaining __init__ docstrings across the entire codebase."""

import re
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple

def get_missing_docstring_files() -> List[Tuple[str, int]]:
    """Get all files with missing __init__ docstrings."""
    try:
        result = subprocess.run(
            ["ruff", "check", "--select", "D107", "."],
            capture_output=True,
            text=True,
            cwd="C:/Intellicrack"
        )
        
        files_and_lines = []
        for line in result.stdout.strip().split('\n'):
            if "D107 Missing docstring in `__init__`" in line:
                # Extract file path and line number
                match = re.match(r'^([^:]+):(\d+):', line)
                if match:
                    file_path = match.group(1).replace('\\', '/')
                    line_num = int(match.group(2))
                    files_and_lines.append((file_path, line_num))
        
        return files_and_lines
    except Exception as e:
        print(f"Error getting ruff output: {e}")
        return []

def fix_init_docstring_at_line(file_path: str, line_num: int) -> bool:
    """Fix specific __init__ docstring at given line."""
    try:
        full_path = Path("C:/Intellicrack") / file_path
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Find the __init__ line and get method signature
        init_line_idx = line_num - 1
        if init_line_idx >= len(lines):
            return False
            
        init_line = lines[init_line_idx]
        if "def __init__" not in init_line:
            return False
        
        # Get the indentation level
        indent = len(init_line) - len(init_line.lstrip())
        docstring_indent = ' ' * (indent + 4)
        
        # Check if next line already has docstring
        if init_line_idx + 1 < len(lines):
            next_line = lines[init_line_idx + 1].strip()
            if '"""' in next_line:
                return False  # Already has docstring
        
        # Collect the method signature (might span multiple lines)
        method_sig = ""
        i = init_line_idx
        paren_count = 0
        while i < len(lines):
            line = lines[i]
            method_sig += line.strip() + " "
            paren_count += line.count('(') - line.count(')')
            if paren_count == 0 and line.strip().endswith(':'):
                break
            i += 1
        
        # Generate appropriate docstring based on signature
        docstring = generate_docstring(method_sig, docstring_indent)
        
        # Insert docstring after the method definition line
        insert_line = i + 1
        lines.insert(insert_line, docstring)
        
        # Write back to file
        with open(full_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        return True
        
    except Exception as e:
        print(f"Error fixing {file_path}:{line_num} - {e}")
        return False

def generate_docstring(method_sig: str, indent: str) -> str:
    """Generate appropriate docstring based on method signature."""
    # Extract parameters
    sig_lower = method_sig.lower()
    
    # Common parameter patterns and their descriptions
    param_descriptions = {
        'parent': 'Parent object for proper memory management',
        'config': 'Configuration object',
        'configuration': 'Configuration settings',
        'file_path': 'Path to file',
        'filepath': 'Path to file', 
        'path': 'File or directory path',
        'data': 'Data content',
        'content': 'Content data',
        'result': 'Analysis or processing result',
        'analysis_result': 'Result from analysis operation',
        'engine': 'Engine instance',
        'manager': 'Manager instance',
        'handler': 'Handler object',
        'interface': 'Interface object',
        'model': 'Model object',
        'operation': 'Operation type or identifier',
        'options': 'Configuration options',
        'settings': 'Settings dictionary',
        'args': 'Variable arguments',
        'kwargs': 'Keyword arguments',
    }
    
    # Extract parameter names (simple approach)
    params = re.findall(r'(\w+)(?:\s*:\s*[^,)]+)?(?:\s*=\s*[^,)]+)?', method_sig)
    params = [p for p in params if p not in ['self', 'def', '__init__']]
    
    # Build docstring
    if not params:
        return f'{indent}"""Initialize the object."""\n'
    
    # Create docstring with parameters
    docstring_lines = [f'{indent}"""Initialize the object.\n']
    
    if params:
        docstring_lines.append(f'{indent}\n')
        docstring_lines.append(f'{indent}Args:\n')
        
        for param in params:
            desc = param_descriptions.get(param.lower(), f'{param.replace("_", " ").title()}')
            docstring_lines.append(f'{indent}    {param}: {desc}\n')
    
    docstring_lines.append(f'{indent}"""\n')
    
    return ''.join(docstring_lines)

# Main execution
if __name__ == "__main__":
    print("Getting all missing __init__ docstrings...")
    
    files_and_lines = get_missing_docstring_files()
    
    if not files_and_lines:
        print("No missing __init__ docstrings found!")
        exit(0)
    
    print(f"Found {len(files_and_lines)} missing __init__ docstrings")
    
    # Group by file for efficiency
    files_dict: Dict[str, List[int]] = {}
    for file_path, line_num in files_and_lines:
        if file_path not in files_dict:
            files_dict[file_path] = []
        files_dict[file_path].append(line_num)
    
    # Sort lines in descending order so we can insert from bottom to top
    for file_path in files_dict:
        files_dict[file_path].sort(reverse=True)
    
    fixed_count = 0
    total_count = len(files_and_lines)
    
    for file_path, line_nums in files_dict.items():
        print(f"Processing {file_path} ({len(line_nums)} issues)...")
        for line_num in line_nums:
            if fix_init_docstring_at_line(file_path, line_num):
                fixed_count += 1
    
    print(f"Fixed {fixed_count} out of {total_count} __init__ docstrings")
    
    # Check remaining issues
    remaining = get_missing_docstring_files()
    print(f"Remaining __init__ docstring issues: {len(remaining)}")