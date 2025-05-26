#!/usr/bin/env python3
"""Count the actual functions we have implemented in the modular structure."""

import os
import re
from pathlib import Path

def count_functions_in_file(filepath):
    """Count functions in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all function definitions
        function_pattern = r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        functions = []
        
        for line_num, line in enumerate(content.splitlines(), 1):
            match = re.match(function_pattern, line)
            if match:
                func_name = match.group(1)
                functions.append({
                    'name': func_name,
                    'line': line_num,
                    'file': filepath
                })
        
        return functions
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return []

def count_modular_functions():
    """Count all functions in the modular structure."""
    all_functions = []
    file_counts = {}
    
    # Walk through the intellicrack directory
    for root, dirs, files in os.walk('intellicrack'):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                functions = count_functions_in_file(filepath)
                
                if functions:
                    file_counts[filepath] = len(functions)
                    all_functions.extend(functions)
    
    return all_functions, file_counts

def main():
    print("=== ACTUAL MODULAR FUNCTION COUNT ===\n")
    
    functions, file_counts = count_modular_functions()
    
    print(f"Total files analyzed: {len(file_counts)}")
    print(f"Total functions found: {len(functions)}")
    
    # Show breakdown by file
    print(f"\n=== FUNCTIONS BY FILE ===")
    for filepath, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{count:3d} functions - {filepath}")
    
    # Show breakdown by directory
    print(f"\n=== FUNCTIONS BY DIRECTORY ===")
    dir_counts = {}
    for filepath, count in file_counts.items():
        dir_path = os.path.dirname(filepath)
        dir_counts[dir_path] = dir_counts.get(dir_path, 0) + count
    
    for dirpath, count in sorted(dir_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{count:3d} functions - {dirpath}")
    
    # Check for duplicates
    function_names = [f['name'] for f in functions]
    unique_names = set(function_names)
    
    print(f"\n=== FUNCTION NAME ANALYSIS ===")
    print(f"Total function calls: {len(function_names)}")
    print(f"Unique function names: {len(unique_names)}")
    print(f"Duplicate names: {len(function_names) - len(unique_names)}")
    
    # Find most common function names
    from collections import Counter
    name_counts = Counter(function_names)
    most_common = name_counts.most_common(10)
    
    print(f"\nMost common function names:")
    for name, count in most_common:
        if count > 1:
            print(f"  {name}: {count} times")
    
    # Show some example functions
    print(f"\n=== SAMPLE FUNCTIONS ===")
    for func in functions[:20]:
        print(f"  {func['name']} - {func['file']}:{func['line']}")
    
    if len(functions) > 20:
        print(f"  ... and {len(functions) - 20} more")

if __name__ == '__main__':
    main()