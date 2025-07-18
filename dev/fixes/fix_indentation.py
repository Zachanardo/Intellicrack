#!/usr/bin/env python3
"""
Quick script to fix indentation errors after docstring additions.
Fixes the common pattern where code after docstrings loses its indentation.
"""

import os
import re
import sys

def fix_indentation_in_file(filepath):
    """Fix indentation issues in a single Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        lines = content.split('\n')
        fixed_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i]
            fixed_lines.append(line)
            
            # Look for docstring end patterns
            if line.strip() == '"""' or line.strip().endswith('"""'):
                # Check if next line exists and is not properly indented
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    
                    # If next line has content but is not indented properly
                    if next_line.strip() and not next_line.startswith('    ') and not next_line.startswith('\t'):
                        # Determine proper indentation level
                        # Look back to find the function/class definition
                        indent_level = 0
                        for j in range(i, -1, -1):
                            if lines[j].strip().startswith('def ') or lines[j].strip().startswith('class '):
                                indent_level = len(lines[j]) - len(lines[j].lstrip())
                                break
                        
                        # Add 4 spaces for method/function content
                        if lines[j].strip().startswith('def '):
                            indent_level += 4
                        
                        # Fix the next line's indentation
                        if next_line.strip():
                            fixed_next_line = ' ' * indent_level + next_line.strip()
                            lines[i + 1] = fixed_next_line
            
            i += 1
        
        # Join the fixed lines
        fixed_content = '\n'.join(lines)
        
        # Additional patterns to fix common issues
        patterns = [
            # Fix unindented code after docstrings
            (r'    """\n([a-zA-Z_])', r'    """\n        \1'),
            # Fix specific patterns we've seen
            (r'    """\nsuper\(\)', r'    """\n        super()'),
            (r'    """\nself\.', r'    """\n        self.'),
            (r'    """\nif ', r'    """\n        if '),
            (r'    """\nfor ', r'    """\n        for '),
            (r'    """\nreturn ', r'    """\n        return '),
            (r'    """\ntry:', r'    """\n        try:'),
            (r'    """\nconfig = ', r'    """\n        config = '),
        ]
        
        for pattern, replacement in patterns:
            fixed_content = re.sub(pattern, replacement, fixed_content)
        
        # Write back if changed
        if fixed_content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            print(f"Fixed: {filepath}")
            return True
        else:
            print(f"No changes: {filepath}")
            return False
            
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix indentation in all Python files with known issues."""
    
    files_with_errors = [
        "intellicrack/core/frida_manager.py",
        "intellicrack/core/gpu_acceleration.py", 
        "intellicrack/core/task_manager.py",
        "intellicrack/core/analysis/analysis_orchestrator.py",
        "intellicrack/core/analysis/binary_similarity_search.py",
        "intellicrack/core/analysis/cfg_explorer.py",
        "intellicrack/core/analysis/concolic_executor.py",
        "intellicrack/core/analysis/concolic_executor_fixed.py",
        "intellicrack/core/analysis/dynamic_analyzer.py",
        "intellicrack/core/analysis/entropy_analyzer.py",
    ]
    
    fixed_count = 0
    
    for file_path in files_with_errors:
        if os.path.exists(file_path):
            if fix_indentation_in_file(file_path):
                fixed_count += 1
        else:
            print(f"File not found: {file_path}")
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    os.chdir("C:/Intellicrack")
    main()