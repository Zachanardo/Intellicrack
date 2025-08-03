#!/usr/bin/env python3
"""
Rebuild the symbolic_executor.py file with proper structure.
"""

import sys
import subprocess
from pathlib import Path

def main():
    filepath = Path(r"C:\Intellicrack\intellicrack\core\analysis\symbolic_executor.py")

    # Read the file
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split into lines and rebuild with proper structure
    lines = content.splitlines()
    fixed_lines = []

    in_try_block = False
    try_indent = 0

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)

        # Handle try blocks
        if stripped == 'try:':
            in_try_block = True
            try_indent = current_indent
            fixed_lines.append(line)
            i += 1
            continue

        # Handle except blocks
        if stripped.startswith('except ') and in_try_block:
            # Make sure it's at the right level
            if current_indent != try_indent:
                fixed_lines.append(' ' * try_indent + stripped)
            else:
                fixed_lines.append(line)
            in_try_block = False
            i += 1
            continue

        # Handle orphaned except blocks (remove duplicates)
        if stripped.startswith('except ') and not in_try_block:
            # Check if this is a duplicate
            if i > 0 and any('except' in fl for fl in fixed_lines[-3:]):
                # Skip duplicate except
                i += 1
                continue

        # Handle else blocks
        if stripped == 'else:':
            # Check if this belongs to an if or for
            recent_lines = fixed_lines[-10:] if len(fixed_lines) >= 10 else fixed_lines
            has_matching_structure = False

            for recent_line in reversed(recent_lines):
                recent_stripped = recent_line.lstrip()
                if recent_stripped.startswith(('if ', 'elif ', 'for ', 'while ', 'try:')):
                    has_matching_structure = True
                    break

            if has_matching_structure:
                fixed_lines.append(line)
            else:
                # Skip orphaned else
                pass
            i += 1
            continue

        # Regular lines
        fixed_lines.append(line)
        i += 1

    # Join back together
    fixed_content = '\n'.join(fixed_lines)

    # Fix remaining specific issues
    # Remove import re from inside methods
    import re
    fixed_content = re.sub(r'\n        import re\n', r'\n', fixed_content)

    # Ensure import re is at the top if needed
    if 'import re' not in fixed_content[:500]:  # Check if it's already at the top
        # Add import re after other imports
        lines = fixed_content.split('\n')
        import_end_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                import_end_idx = i

        lines.insert(import_end_idx + 1, 'import re')
        fixed_content = '\n'.join(lines)

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print("Rebuilt symbolic_executor.py with proper structure")

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
            # Print just the first error line to avoid spam
            error_lines = result.stderr.split('\n')
            for line in error_lines:
                if 'File "' in line and 'symbolic_executor.py' in line:
                    print(line)
                    break
            else:
                print(result.stderr[:500])
    else:
        print(f"Still has syntax errors: {result.stderr}")
        # Show line number
        error_lines = result.stderr.split('\n')
        for line in error_lines:
            if 'line ' in line:
                print(line)
                break

if __name__ == '__main__':
    main()
