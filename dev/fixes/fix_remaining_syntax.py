#!/usr/bin/env python3
"""
Comprehensive syntax error fixer - handles all remaining patterns.
"""

import os
import ast
import re

def get_syntax_error_details(filepath):
    """Get specific syntax error details for a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        ast.parse(content)
        return None  # No syntax error
    except SyntaxError as e:
        return {
            'line': e.lineno,
            'text': e.text,
            'msg': e.msg,
            'offset': e.offset
        }
    except Exception:
        return {'msg': 'Other error'}

def fix_syntax_error(filepath, error_info):
    """Fix specific syntax error in file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if not error_info or 'line' not in error_info:
            return False

        error_line = error_info['line'] - 1  # Convert to 0-based

        if error_line >= len(lines):
            return False

        line = lines[error_line]
        modified = False

        # Common patterns and fixes

        # 1. Missing opening docstring quotes
        if 'invalid decimal literal' in error_info.get('msg', '') and line.strip().endswith('"""'):
            # Look for previous lines that might be part of a docstring
            for i in range(max(0, error_line - 10), error_line):
                if not lines[i].strip().startswith('#') and lines[i].strip():
                    lines[i] = '"""' + lines[i]
                    modified = True
                    break

        # 2. Incorrect indentation - code not indented after docstring
        elif 'unexpected indent' in error_info.get('msg', ''):
            # Check if this line should be unindented (imports, class/function definitions)
            if (line.strip().startswith(('import ', 'from ', 'class ', 'def ')) and
                line.startswith('    ')):
                lines[error_line] = line[4:]  # Remove 4 spaces
                modified = True
            # Check if line should be more indented (method body)
            elif not line.startswith('    ') and line.strip():
                # Look back to find context
                for i in range(error_line - 1, max(0, error_line - 5), -1):
                    if 'def ' in lines[i] or 'class ' in lines[i]:
                        # This should be indented as method/class body
                        lines[error_line] = '    ' + line.lstrip()
                        modified = True
                        break

        # 3. Missing docstring end quotes
        elif 'EOF while scanning triple-quoted string literal' in error_info.get('msg', ''):
            # Add closing quotes at the end of file or appropriate location
            if not any('"""' in line for line in lines[error_line:]):
                lines.append('"""\n')
                modified = True

        # 4. Indentation inconsistency
        elif 'unindent does not match any outer indentation level' in error_info.get('msg', ''):
            # Fix indentation to match surrounding context
            target_indent = 0
            for i in range(error_line - 1, -1, -1):
                if lines[i].strip() and not lines[i].strip().startswith('#'):
                    target_indent = len(lines[i]) - len(lines[i].lstrip())
                    break

            if line.strip():
                lines[error_line] = ' ' * target_indent + line.lstrip()
                modified = True

        # 5. General indentation fixes
        elif 'IndentationError' in str(error_info.get('msg', '')):
            # Try to fix based on surrounding context
            if error_line > 0:
                prev_line = lines[error_line - 1]
                if prev_line.strip().endswith(':'):
                    # Should be indented relative to previous line
                    prev_indent = len(prev_line) - len(prev_line.lstrip())
                    lines[error_line] = ' ' * (prev_indent + 4) + line.lstrip()
                    modified = True

        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True

        return False

    except Exception as e:
        print(f"Error fixing {filepath}: {e}")
        return False

def main():
    os.chdir('C:/Intellicrack')

    # Get all Python files with syntax errors
    error_files = []
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                error_info = get_syntax_error_details(filepath)
                if error_info:
                    error_files.append((filepath, error_info))

    print(f"Found {len(error_files)} files with syntax errors")

    fixed_count = 0

    for filepath, error_info in error_files:
        print(f"Fixing {filepath}: {error_info.get('msg', 'Unknown error')}")
        if fix_syntax_error(filepath, error_info):
            fixed_count += 1
            print(f"  ✓ Fixed")
        else:
            print(f"  ✗ Could not fix automatically")

    print(f"\nAttempted to fix {fixed_count} files")

    # Final verification
    print("\nFinal verification...")
    remaining_errors = []
    for root, dirs, files in os.walk('intellicrack'):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                if get_syntax_error_details(filepath):
                    remaining_errors.append(filepath)

    print(f"Remaining files with syntax errors: {len(remaining_errors)}")

    if remaining_errors and len(remaining_errors) <= 10:
        print("Files still with errors:")
        for f in remaining_errors:
            error_info = get_syntax_error_details(f)
            print(f"  {f}: {error_info.get('msg', 'Unknown')}")

if __name__ == "__main__":
    main()
