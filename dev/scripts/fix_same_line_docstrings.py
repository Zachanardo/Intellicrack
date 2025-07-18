#!/usr/bin/env python3
"""
Fix the specific pattern: '''docstring'''        code
This is causing most of the syntax errors.
"""

import os
import re
import sys
import subprocess
from pathlib import Path

def fix_same_line_docstrings(content: str) -> str:
    """Fix docstrings that have code on the same line."""
    
    # Pattern: """docstring"""        code
    # Replace with: """docstring"""
    #               code (properly indented)
    
    lines = content.splitlines(keepends=True)
    fixed_lines = []
    
    for line in lines:
        # Check for the problematic pattern
        match = re.match(r'^(\s*)("""[^"]*"""|\'\'\'[^\']*\'\'\')(\s+)(.+)$', line)
        if match:
            indent = match.group(1)
            docstring = match.group(2)
            code = match.group(4)
            
            # Split into two lines
            fixed_lines.append(f"{indent}{docstring}\n")
            
            # Determine proper indentation for the code
            # If we're in a method (8+ spaces), keep the same indentation
            # Otherwise use 4 spaces more than the docstring
            if len(indent) >= 8:
                code_indent = indent
            else:
                code_indent = indent + "    "
            
            fixed_lines.append(f"{code_indent}{code}\n")
        else:
            fixed_lines.append(line)
    
    return ''.join(fixed_lines)

def check_syntax(filepath: Path) -> bool:
    """Check if file has syntax errors."""
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'py_compile', str(filepath)],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def main():
    root_dir = Path(r"C:\Intellicrack")
    
    # Get all Python files
    python_files = []
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in {'.venv', '__pycache__', '.git', 'venv', '.venv_wsl', '.venv_windows'}]
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
    
    print(f"Processing {len(python_files)} Python files...")
    
    fixed_count = 0
    
    for filepath in python_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file has the problematic pattern
            if re.search(r'"""[^"]*"""\s+[^\n\r\s]', content) or re.search(r"'''[^']*'''\s+[^\n\r\s]", content):
                original_content = content
                fixed_content = fix_same_line_docstrings(content)
                
                if fixed_content != original_content:
                    # Write the fixed content
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    
                    # Verify the fix
                    if check_syntax(filepath):
                        print(f"Fixed: {filepath.relative_to(root_dir)}")
                        fixed_count += 1
                    else:
                        print(f"Fix failed for: {filepath.relative_to(root_dir)}")
                        # Restore original content if fix didn't work
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(original_content)
        
        except Exception as e:
            print(f"Error processing {filepath}: {e}")
    
    print(f"\nFixed {fixed_count} files")
    
    # Test import
    print("\nTesting import...")
    result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
    if result.returncode == 0:
        print("SUCCESS: intellicrack imports correctly!")
    else:
        print("Import still has errors:")
        print(result.stderr)

if __name__ == '__main__':
    main()