#!/usr/bin/env python3
"""
Fix a specific file's indentation issues systematically.
"""

import re
import sys
import subprocess
from pathlib import Path

def fix_indentation_issues(content: str) -> str:
    """Fix common indentation patterns."""
    lines = content.splitlines()
    fixed_lines = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)
        
        # Fix try blocks
        if stripped == 'try:':
            fixed_lines.append(line)
            # Fix the next lines to be properly indented
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                next_stripped = next_line.lstrip()
                next_indent = len(next_line) - len(next_stripped)
                
                if not next_stripped:  # Empty line
                    fixed_lines.append(next_line)
                    j += 1
                    continue
                
                if next_stripped.startswith(('except', 'finally', 'else:')):
                    # These should be at the same level as try
                    fixed_lines.append(' ' * current_indent + next_stripped)
                    break
                elif next_indent <= current_indent and next_stripped and not next_stripped.startswith('#'):
                    # This should be indented inside the try block
                    fixed_lines.append(' ' * (current_indent + 4) + next_stripped)
                else:
                    fixed_lines.append(next_line)
                    if next_indent <= current_indent and next_stripped:
                        break
                j += 1
            i = j
            continue
        
        # Fix imports at module level
        if stripped.startswith(('import ', 'from ')) and current_indent > 0:
            fixed_lines.append(stripped)
            i += 1
            continue
        
        # Fix function/method definitions
        if stripped.startswith(('def ', 'async def ')):
            # Keep the definition as is
            fixed_lines.append(line)
            i += 1
            continue
        
        # Regular line
        fixed_lines.append(line)
        i += 1
    
    return '\n'.join(fixed_lines)

def main():
    filepath = Path(r"C:\Intellicrack\intellicrack\core\analysis\symbolic_executor.py")
    
    # Read the file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Apply fixes
    fixed_content = fix_indentation_issues(content)
    
    # Additional specific fixes for this file
    # Fix the import re that got misplaced
    fixed_content = re.sub(r'\n        # ASCII strings\nimport re', r'\n        # ASCII strings\n        import re', fixed_content)
    
    # Fix other common patterns
    fixed_content = re.sub(r'(\s+)(ascii_pattern = re\.compile\()', r'        \2', fixed_content)
    
    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    # Test syntax
    result = subprocess.run([sys.executable, '-m', 'py_compile', str(filepath)], capture_output=True, text=True)
    if result.returncode == 0:
        print("File syntax is now correct!")
        
        # Test import
        result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
        if result.returncode == 0:
            print("SUCCESS: intellicrack imports correctly!")
        else:
            print("Import still has errors:")
            print(result.stderr)
    else:
        print(f"Still has syntax errors: {result.stderr}")

if __name__ == '__main__':
    main()