#!/usr/bin/env python3
"""
Comprehensive fix for symbolic_executor.py indentation and structure issues.
"""

import re
import sys
import subprocess
from pathlib import Path

def main():
    filepath = Path(r"C:\Intellicrack\intellicrack\core\analysis\symbolic_executor.py")

    # Read the file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Fix major structural issues

    # 1. Fix duplicate else statements
    content = re.sub(r'        else:\n(\s+)else:', r'        else:', content)

    # 2. Fix malformed try blocks - remove standalone else statements
    lines = content.splitlines()
    fixed_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Skip standalone else statements that don't belong to if/try
        if stripped == 'else:' and i > 0:
            # Check if this belongs to an if or try
            prev_lines = fixed_lines[-5:] if len(fixed_lines) >= 5 else fixed_lines
            has_if_or_try = any('if ' in l or 'try:' in l for l in prev_lines)

            if not has_if_or_try:
                # Skip this orphaned else
                i += 1
                continue

        fixed_lines.append(line)
        i += 1

    content = '\n'.join(fixed_lines)

    # 3. Fix import re placement
    content = re.sub(r'        # ASCII strings\n        import re', r'        # ASCII strings\n        import re', content)

    # 4. Fix common indentation patterns
    content = re.sub(r'^(\s*)import re$', r'import re', content, flags=re.MULTILINE)
    content = re.sub(r'^        import re$', r'import re', content, flags=re.MULTILINE)

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Applied comprehensive fixes to symbolic_executor.py")

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
