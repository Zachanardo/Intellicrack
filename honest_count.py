#!/usr/bin/env python3
"""Honest count of ONLY the modular structure, excluding the monolithic file."""

import os
import re

def count_only_modular():
    """Count functions ONLY in the modular structure, excluding Intellicrack.py."""
    
    # Get all Python files in intellicrack directory ONLY
    python_files = []
    for root, dirs, files in os.walk('intellicrack'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                python_files.append(filepath)
    
    print(f"Scanning ONLY modular files (excluding Intellicrack.py):")
    print(f"Found {len(python_files)} Python files in intellicrack/ directory\n")
    
    total_functions = 0
    file_details = []
    
    for filepath in python_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Count functions in this file
            function_pattern = r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            functions = re.findall(function_pattern, content, re.MULTILINE)
            
            if functions:
                file_details.append((filepath, len(functions), functions))
                total_functions += len(functions)
                print(f"{len(functions):3d} functions - {filepath}")
            else:
                print(f"  0 functions - {filepath}")
                
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
    
    print(f"\n=== SUMMARY ===")
    print(f"Total Python files in modular structure: {len(python_files)}")
    print(f"Files with functions: {len(file_details)}")
    print(f"Total functions implemented: {total_functions}")
    
    # Show breakdown by size
    print(f"\n=== LARGEST FILES ===")
    file_details.sort(key=lambda x: x[1], reverse=True)
    for filepath, count, functions in file_details[:15]:
        print(f"{count:3d} functions - {filepath}")
    
    # Show some example function names from largest files
    print(f"\n=== SAMPLE FUNCTIONS FROM LARGEST FILES ===")
    for filepath, count, functions in file_details[:5]:
        print(f"\n{filepath} ({count} functions):")
        for func in functions[:10]:
            print(f"  - {func}")
        if len(functions) > 10:
            print(f"  ... and {len(functions) - 10} more")
    
    return total_functions, file_details

def main():
    print("=== HONEST COUNT OF MODULAR IMPLEMENTATION ===")
    print("(Excluding the monolithic Intellicrack.py file)\n")
    
    total, details = count_only_modular()
    
    print(f"\n🎯 ACTUAL MODULAR IMPLEMENTATION: {total} functions")
    
    # Check if Intellicrack.py exists and mention it's excluded
    if os.path.exists('Intellicrack.py'):
        print(f"📝 Note: Intellicrack.py exists but is EXCLUDED from this count")
        print(f"📝 This count represents ONLY our modular refactoring work")

if __name__ == '__main__':
    main()