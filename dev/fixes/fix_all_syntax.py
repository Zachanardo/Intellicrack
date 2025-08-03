#!/usr/bin/env python3
import os
import sys
import ast

def fix_indentation_after_docstring(filepath):
    """Fix indentation issues after docstrings in Python files."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        modified = False
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()

            # Check if this line ends a docstring
            if line.strip() == '"""' or (line.strip().endswith('"""') and len(line.strip()) > 3):
                # Look at the next non-empty line
                j = i + 1
                while j < len(lines) and lines[j].strip() == '':
                    j += 1

                if j < len(lines):
                    next_line = lines[j]
                    # If the next line has content but wrong indentation
                    if next_line.strip() and not next_line.startswith('    ') and not next_line.startswith('\t'):
                        # Find the expected indentation by looking at the function/class definition
                        expected_indent = 8  # Default for method content

                        # Look backwards to find the function/class def
                        for k in range(i, -1, -1):
                            if 'def ' in lines[k] or 'class ' in lines[k]:
                                base_indent = len(lines[k]) - len(lines[k].lstrip())
                                if 'def ' in lines[k]:
                                    expected_indent = base_indent + 4
                                else:
                                    expected_indent = base_indent + 4
                                break

                        # Fix the indentation
                        lines[j] = ' ' * expected_indent + next_line.lstrip()
                        modified = True

            i += 1

        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True
        return False

    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def get_files_with_syntax_errors():
    """Get list of files with syntax errors."""
    files_with_errors = []

    # Walk through intellicrack directory
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        ast.parse(f.read())
                except SyntaxError:
                    files_with_errors.append(filepath)
                except Exception:
                    pass  # Skip files that can't be read

    return files_with_errors

def main():
    os.chdir('C:/Intellicrack')

    print("Finding files with syntax errors...")
    error_files = get_files_with_syntax_errors()

    print(f"Found {len(error_files)} files with syntax errors")

    fixed_count = 0
    for filepath in error_files:
        print(f"Fixing {filepath}...")
        if fix_indentation_after_docstring(filepath):
            fixed_count += 1
            print(f"  ✓ Fixed")
        else:
            print(f"  - No changes needed")

    print(f"\nFixed {fixed_count} files")

    # Verify fixes
    print("\nVerifying fixes...")
    remaining_errors = get_files_with_syntax_errors()
    print(f"Remaining files with syntax errors: {len(remaining_errors)}")

    if remaining_errors:
        print("Files still with errors:")
        for f in remaining_errors[:10]:  # Show first 10
            print(f"  {f}")

if __name__ == "__main__":
    main()
