#!/usr/bin/env python3
"""
Fixed script to handle docstring indentation issues.
"""

import os
import re

def fix_docstring_indentation(filepath):
    """Fix incorrect docstring indentation patterns."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix the specific pattern: function definition followed by incorrectly indented docstring
        # Pattern: def func():\n       """docstring (7 spaces instead of 8)
        content = re.sub(
            r'(def [^:]+:)\n       (""")',
            r'\1\n        \2',
            content
        )
        
        # Pattern: __init__(...):\n       """docstring
        content = re.sub(
            r'(__init__[^:]+:)\n       (""")',
            r'\1\n        \2',
            content
        )
        
        # Write back if changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed: {filepath}")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all files in the analysis directory and other problematic files."""
    
    base_dir = "C:/Intellicrack/intellicrack"
    
    # Files with known issues
    files_to_fix = []
    
    # Get all Python files in core/analysis directory
    analysis_dir = os.path.join(base_dir, "core/analysis")
    if os.path.exists(analysis_dir):
        for file in os.listdir(analysis_dir):
            if file.endswith('.py'):
                files_to_fix.append(os.path.join(analysis_dir, file))
    
    # Add other specific files
    other_files = [
        "core/anti_analysis/__init__.py",
        "core/anti_analysis/api_obfuscation.py", 
        "core/anti_analysis/base_detector.py",
        "core/anti_analysis/debugger_detector.py",
        "core/anti_analysis/process_hollowing.py",
        "core/anti_analysis/sandbox_detector.py",
        "core/anti_analysis/timing_attacks.py",
        "core/anti_analysis/vm_detector.py",
    ]
    
    for file_path in other_files:
        full_path = os.path.join(base_dir, file_path)
        if os.path.exists(full_path):
            files_to_fix.append(full_path)
    
    fixed_count = 0
    os.chdir("C:/Intellicrack")
    
    for file_path in files_to_fix:
        if fix_docstring_indentation(file_path):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()