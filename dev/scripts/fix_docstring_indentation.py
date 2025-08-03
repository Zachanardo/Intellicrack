#!/usr/bin/env python3
"""
Advanced indentation fixer for docstring-related syntax errors.
Specifically targets the pattern where docstrings and code are on the same line.
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional

class AdvancedIndentationFixer:
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.fixed_files = []
        self.failed_files = []

    def check_syntax(self, filepath: Path) -> Optional[str]:
        """Check if a file has syntax errors."""
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'py_compile', str(filepath)],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return result.stderr
            return None
        except Exception as e:
            return str(e)

    def fix_file(self, filepath: Path) -> bool:
        """Fix a single file with advanced patterns."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content

            # Pattern 1: Fix docstring-code same line issues
            # Match: """docstring"""        code
            content = re.sub(
                r'(    """[^"]*"""|\'\'\'\'\')(\s+)([^\n\r\s][^\n\r]*)',
                r'\1\n        \3',
                content,
                flags=re.MULTILINE
            )

            # Pattern 2: Fix try/except blocks that lost indentation
            lines = content.splitlines()
            fixed_lines = []

            for i, line in enumerate(lines):
                stripped = line.lstrip()
                current_indent = len(line) - len(stripped)

                # Fix try blocks without proper indentation
                if stripped == 'try:' and i < len(lines) - 1:
                    next_line = lines[i + 1] if i + 1 < len(lines) else ""
                    next_stripped = next_line.lstrip()
                    next_indent = len(next_line) - len(next_stripped)

                    # If next line isn't properly indented
                    if next_stripped and next_indent <= current_indent:
                        fixed_lines.append(line)
                        # Look ahead and fix the following lines
                        j = i + 1
                        while j < len(lines):
                            look_line = lines[j]
                            look_stripped = look_line.lstrip()
                            look_indent = len(look_line) - len(look_stripped)

                            if not look_stripped:  # Empty line
                                fixed_lines.append(look_line)
                            elif look_stripped.startswith(('except', 'finally', 'else:')):
                                # These should be at the same level as try
                                fixed_lines.append(' ' * current_indent + look_stripped)
                                break
                            elif look_indent <= current_indent and look_stripped and not look_stripped.startswith('#'):
                                # This should be indented inside the try block
                                fixed_lines.append(' ' * (current_indent + 4) + look_stripped)
                            else:
                                fixed_lines.append(look_line)
                                if look_indent <= current_indent:
                                    break
                            j += 1
                        i = j - 1  # Skip the lines we just processed
                        continue

                # Fix imports that got indented
                if stripped.startswith(('import ', 'from ')) and current_indent > 0:
                    fixed_lines.append(stripped)
                    continue

                # Fix class/function definitions that lost proper structure
                if stripped.startswith(('class ', 'def ', 'async def ')):
                    # Ensure proper indentation context
                    if current_indent == 0 or (current_indent == 4 and any(l.strip().startswith('class ') for l in lines[:i])):
                        fixed_lines.append(line)
                    else:
                        # Fix indentation based on context
                        in_class = any(l.strip().startswith('class ') and len(l) - len(l.lstrip()) < current_indent
                                     for l in lines[:i])
                        if in_class and stripped.startswith('def '):
                            fixed_lines.append('    ' + stripped)  # Method in class
                        else:
                            fixed_lines.append(stripped)  # Module level
                    continue

                fixed_lines.append(line)

            content = '\n'.join(fixed_lines)

            # Pattern 3: Fix specific @property/@abstractmethod issues
            content = re.sub(
                r'(\s+)@property\n(\s+)def ([^:]+):(\s+)"""([^"]+)"""(\s+)([^\n]+)',
                r'\1@property\n\1def \3:\n\1    """\5"""\n\1    \7',
                content,
                flags=re.MULTILINE | re.DOTALL
            )

            # Pattern 4: Fix abstractmethod decorator issues
            content = re.sub(
                r'(\s+)@abstractmethod\n(\s+)def ([^:]+):(\s+)"""([^"]+)"""(\s+)([^\n]+)',
                r'\1@abstractmethod\n\1def \3:\n\1    """\5"""\n\1    \7',
                content,
                flags=re.MULTILINE | re.DOTALL
            )

            # Only write if content changed
            if content != original_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True

            return False

        except Exception as e:
            print(f"Error fixing {filepath}: {e}")
            return False

    def run_on_specific_file(self, filepath: Path) -> bool:
        """Run the fixer on a specific file."""
        print(f"Fixing {filepath.relative_to(self.root_dir)}...")

        # Check initial syntax
        error = self.check_syntax(filepath)
        if not error:
            print("  File already has no syntax errors")
            return True

        # Apply fix
        if self.fix_file(filepath):
            # Check if fix worked
            error = self.check_syntax(filepath)
            if error:
                print(f"  Still has errors: {error.strip()}")
                return False
            else:
                print("  Fixed successfully!")
                return True
        else:
            print("  No changes made")
            return False

def main():
    # Get the problematic file from the error
    root_dir = Path(r"C:\Intellicrack")
    fixer = AdvancedIndentationFixer(root_dir)

    # Start with the specific file causing the import error
    symbolic_executor = root_dir / "intellicrack" / "core" / "analysis" / "symbolic_executor.py"

    if symbolic_executor.exists():
        print("Fixing symbolic_executor.py first...")
        if fixer.run_on_specific_file(symbolic_executor):
            # Test import again
            print("\nTesting import after fixing symbolic_executor...")
            result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
            if result.returncode == 0:
                print("SUCCESS: intellicrack imports correctly!")
                return
            else:
                print("Still has import errors, continuing with other files...")
                print(result.stderr)

    # If still failing, get all files with syntax errors and fix them
    print("\nFinding all files with syntax errors...")
    python_files = []
    for root, dirs, files in os.walk(root_dir):
        # Skip virtual environments and cache directories
        dirs[:] = [d for d in dirs if d not in {'.venv', '__pycache__', '.git', 'venv', '.venv_wsl', '.venv_windows'}]
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)

    files_with_errors = []
    for filepath in python_files:
        error = fixer.check_syntax(filepath)
        if error and ('IndentationError' in error or 'SyntaxError' in error):
            files_with_errors.append(filepath)

    print(f"Found {len(files_with_errors)} files with syntax errors")

    # Fix them in order of importance (core files first)
    core_files = [f for f in files_with_errors if 'core' in str(f)]
    other_files = [f for f in files_with_errors if 'core' not in str(f)]

    all_files = core_files + other_files

    for filepath in all_files:
        fixer.run_on_specific_file(filepath)

        # Test import after each core file
        if 'core' in str(filepath):
            result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
            if result.returncode == 0:
                print("SUCCESS: intellicrack imports correctly!")
                return

    # Final test
    print("\nFinal import test...")
    result = subprocess.run([sys.executable, '-c', 'import intellicrack'], capture_output=True, text=True)
    if result.returncode == 0:
        print("SUCCESS: intellicrack imports correctly!")
    else:
        print("FAILED: Still has import errors")
        print(result.stderr)

if __name__ == '__main__':
    main()
