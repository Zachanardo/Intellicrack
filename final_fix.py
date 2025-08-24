#!/usr/bin/env python3
"""Final comprehensive fix using AST parsing and reconstruction."""

import subprocess
import sys


def fix_with_2to3():
    """Use 2to3 to fix indentation issues."""
    file_path = 'intellicrack/ui/dialogs/vulnerability_research_dialog.py'

    # Install lib2to3 if needed
    try:
        from lib2to3 import pygram, pytree, refactor
        from lib2to3.main import StdoutRefactoringTool
    except ImportError:
        print("lib2to3 is part of Python standard library")

    # Try using 2to3 to fix indentation
    result = subprocess.run([
        sys.executable, "-m", "lib2to3",
        "-f", "all",
        "-w",  # Write back
        "-n",  # No backup
        file_path
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print("2to3 fix applied")
    else:
        print(f"2to3 error: {result.stderr}")

def manual_comprehensive_fix():
    """Manually fix the file line by line with proper indentation."""

    file_path = 'intellicrack/ui/dialogs/vulnerability_research_dialog.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split into lines
    lines = content.split('\n')

    fixed_lines = []
    in_class = False
    in_function = False
    in_nested_function = False
    current_indent = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Empty lines
        if not stripped:
            fixed_lines.append('')
            continue

        # Comments
        if stripped.startswith('#'):
            fixed_lines.append(' ' * current_indent + stripped)
            continue

        # Import statements at module level
        if stripped.startswith(('import ', 'from ')) and not in_function:
            # Check if we're in a try block
            if i > 0 and 'try:' in lines[i-1]:
                fixed_lines.append(' ' * 4 + stripped)
            else:
                fixed_lines.append(stripped)
            continue

        # Class definitions
        if stripped.startswith('class '):
            if 'VulnerabilityResearchDialog' in stripped:
                fixed_lines.append(stripped)
                in_class = True
                current_indent = 4
            else:
                # Nested class
                fixed_lines.append(' ' * 4 + stripped)
                current_indent = 8
            continue

        # Function/method definitions
        if stripped.startswith('def '):
            if in_class:
                if in_nested_function:
                    # Nested function inside a method
                    fixed_lines.append(' ' * 12 + stripped)
                    current_indent = 16
                elif 'self' in stripped or 'cls' in stripped:
                    # Class method
                    if current_indent == 8:  # In nested class
                        fixed_lines.append(' ' * 8 + stripped)
                        current_indent = 12
                    else:
                        fixed_lines.append(' ' * 4 + stripped)
                        current_indent = 8
                    in_function = True
                else:
                    # Nested function
                    fixed_lines.append(' ' * 8 + stripped)
                    current_indent = 12
                    in_nested_function = True
            else:
                # Module level function
                fixed_lines.append(stripped)
                current_indent = 4
                in_function = True
            continue

        # Docstrings
        if stripped.startswith('"""'):
            fixed_lines.append(' ' * current_indent + stripped)
            continue

        # Try/except/finally blocks
        if stripped == 'try:':
            fixed_lines.append(' ' * current_indent + 'try:')
            current_indent += 4
            continue

        if stripped.startswith('except'):
            current_indent -= 4
            fixed_lines.append(' ' * current_indent + stripped)
            current_indent += 4
            continue

        if stripped == 'finally:':
            current_indent -= 4
            fixed_lines.append(' ' * current_indent + 'finally:')
            current_indent += 4
            continue

        # If/elif/else blocks
        if stripped.startswith(('if ', 'elif ')):
            fixed_lines.append(' ' * current_indent + stripped)
            continue

        if stripped == 'else:':
            fixed_lines.append(' ' * current_indent + 'else:')
            continue

        # For/while loops
        if stripped.startswith(('for ', 'while ')):
            fixed_lines.append(' ' * current_indent + stripped)
            continue

        # With statements
        if stripped.startswith('with '):
            fixed_lines.append(' ' * current_indent + stripped)
            continue

        # Return statements
        if stripped.startswith('return '):
            fixed_lines.append(' ' * current_indent + stripped)
            # Check if this ends a function
            if i + 1 < len(lines) and lines[i + 1].strip().startswith(('def ', 'class ')):
                if in_nested_function:
                    in_nested_function = False
                    current_indent = 8
                elif in_function:
                    in_function = False
                    current_indent = 4 if in_class else 0
            continue

        # Pass statements
        if stripped == 'pass':
            fixed_lines.append(' ' * current_indent + 'pass')
            continue

        # Regular code lines
        fixed_lines.append(' ' * current_indent + stripped)

    # Write the fixed content
    fixed_content = '\n'.join(fixed_lines)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(fixed_content)

    print("Manual comprehensive fix applied")

def validate_and_format():
    """Validate syntax and apply final formatting."""

    file_path = 'intellicrack/ui/dialogs/vulnerability_research_dialog.py'

    # Check syntax
    result = subprocess.run([
        sys.executable, "-m", "py_compile",
        file_path
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print("✓ Syntax is valid!")

        # Try black formatting
        result = subprocess.run([
            sys.executable, "-m", "black",
            "--line-length=120",
            "--skip-string-normalization",
            file_path
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("✓ Black formatting successful!")
        else:
            print(f"Black formatting failed: {result.stderr}")
    else:
        print(f"✗ Syntax errors remain: {result.stderr}")
        return False

    return True

def main():
    """Main function to apply all fixes."""

    print("Step 1: Applying manual comprehensive fix...")
    manual_comprehensive_fix()

    print("\nStep 2: Validating and formatting...")
    if validate_and_format():
        print("\n✓ File successfully fixed!")
    else:
        print("\nStep 3: Trying 2to3 as fallback...")
        fix_with_2to3()

        print("\nStep 4: Final validation...")
        validate_and_format()

if __name__ == "__main__":
    main()
