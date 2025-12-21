#!/usr/bin/env python
"""
Fix syntax errors introduced during mock removal.
Final pass to ensure all tests are syntactically correct.
"""

import re
from pathlib import Path

def fix_syntax_errors():
    """Fix indentation and syntax errors in test files."""

    test_dir = Path(r'D:\Intellicrack\tests\unit\core\mitigation_bypass')

    print("=" * 60)
    print("FIXING SYNTAX ERRORS IN TEST FILES")
    print("=" * 60)
    print()

    # Fix test_cfi_bypass.py indentation errors
    cfi_test = test_dir / 'test_cfi_bypass.py'
    if cfi_test.exists():
        print(f"Fixing: {cfi_test.name}")

        with open(cfi_test, encoding='utf-8') as f:
            lines = f.readlines()

        # Fix misplaced assert statements
        fixed_lines = []
        for i, line in enumerate(lines):
            if line.strip().startswith('assert') and i > 0 and not lines[i-1].strip().endswith(':'):
                # Check if this assert is misaligned
                if not line.startswith('        '):
                    # Add proper indentation
                    fixed_lines.append(f'        {line.lstrip()}')
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        with open(cfi_test, 'w', encoding='utf-8') as f:
            f.writelines(fixed_lines)

        print("  OK Fixed indentation errors")

    # Fix test_dep_bypass.py syntax error
    dep_test = test_dir / 'test_dep_bypass.py'
    if dep_test.exists():
        print(f"Fixing: {dep_test.name}")

        with open(dep_test, encoding='utf-8') as f:
            content = f.read()

        # Fix the broken analyzer line
        content = re.sub(
            r'analyzer\.analyze# Return value removed:.*?\n',
            'analyzer["analyze"] = ',
            content
        )

        with open(dep_test, 'w', encoding='utf-8') as f:
            f.write(content)

        print("  OK Fixed analyzer syntax error")

    # Fix test_aslr_bypass.py indentation
    aslr_test = test_dir / 'test_aslr_bypass.py'
    if aslr_test.exists():
        print(f"Fixing: {aslr_test.name}")

        with open(aslr_test, encoding='utf-8') as f:
            lines = f.readlines()

        fixed_lines = []
        for i, line in enumerate(lines):
            if line.strip().startswith('assert') and i > 0:
                # Ensure proper indentation
                if not line.startswith('        '):
                    fixed_lines.append(f'        {line.lstrip()}')
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)

        with open(aslr_test, 'w', encoding='utf-8') as f:
            f.writelines(fixed_lines)

        print("  OK Fixed indentation errors")

    print()
    print("=" * 60)
    print("SYNTAX FIXES COMPLETE")
    print("=" * 60)

def run_syntax_check():
    """Run Python syntax check on all test files."""

    import py_compile
    import traceback

    test_dir = Path(r'D:\Intellicrack\tests\unit\core\mitigation_bypass')

    print("\nRunning syntax validation...")
    print("-" * 40)

    all_valid = True

    for test_file in test_dir.glob('test_*.py'):
        try:
            py_compile.compile(str(test_file), doraise=True)
            print(f"OK {test_file.name}: Valid Python syntax")
        except py_compile.PyCompileError as e:
            print(f"FAIL {test_file.name}: Syntax error")
            print(f"    Line {e.exc_value.lineno}: {e.exc_value.msg}")
            all_valid = False
        except Exception as e:
            print(f"FAIL {test_file.name}: {e}")
            all_valid = False

    return all_valid

if __name__ == "__main__":
    fix_syntax_errors()

    if run_syntax_check():
        print("\nOK All test files have valid Python syntax!")
    else:
        print("\nWARNING  Some files still have syntax errors - manual review needed")
