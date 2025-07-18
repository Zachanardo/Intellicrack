#!/usr/bin/env python3
"""
Final script to properly fix all syntax errors.
"""

import os
import subprocess
import sys

def fix_file_syntax(filepath):
    """Fix syntax errors in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        
        # Fix common patterns:
        # 1. Imports that got indented incorrectly (should be at column 0)
        # 2. Code after docstrings that lost indentation
        
        for i, line in enumerate(lines):
            # Fix imports that got incorrectly indented
            if line.startswith('        import ') or line.startswith('        from '):
                lines[i] = line[8:]  # Remove 8 spaces
                modified = True
            
            # Fix class/function definitions that got incorrectly indented
            elif line.startswith('        class ') or line.startswith('        def '):
                # Check if this should be at module level
                if i == 0 or (i > 0 and not any(lines[j].strip().startswith(('class ', 'def ')) for j in range(max(0, i-10), i))):
                    lines[i] = line[8:]  # Remove 8 spaces
                    modified = True
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            print(f"Fixed basic issues in {filepath}")
        
        return True
        
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    os.chdir('C:/Intellicrack')
    
    # Get list of files with syntax errors
    error_files = []
    
    try:
        result = subprocess.run([
            'python', '-c', 
            '''import os, py_compile, sys
for root, dirs, files in os.walk("intellicrack"):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            try:
                py_compile.compile(path, doraise=True)
            except:
                print(path)'''
        ], capture_output=True, text=True, cwd='C:/Intellicrack')
        
        error_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        
    except Exception as e:
        print(f"Error getting file list: {e}")
        return
    
    print(f"Found {len(error_files)} files with syntax errors")
    
    # Fix each file
    for filepath in error_files:
        if os.path.exists(filepath):
            fix_file_syntax(filepath)
    
    print("Phase 1 complete. Running verification...")
    
    # Verify and count remaining errors
    remaining = 0
    try:
        result = subprocess.run([
            'python', '-c', 
            '''import os, py_compile
count = 0
for root, dirs, files in os.walk("intellicrack"):
    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)
            try:
                py_compile.compile(path, doraise=True)
            except:
                count += 1
print(f"Remaining errors: {count}")'''
        ], capture_output=True, text=True, cwd='C:/Intellicrack')
        
        print(result.stdout.strip())
        
    except Exception as e:
        print(f"Error in verification: {e}")

if __name__ == "__main__":
    main()