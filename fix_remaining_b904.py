#!/usr/bin/env python3
"""Fix remaining B904 issues more comprehensively."""

import os
import re


def fix_file_b904_issues(file_path):
    """Fix B904 issues in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content

        # Pattern 1: raise Exception(...) without from clause
        # Look for 'raise ExceptionType(...)' followed by a newline, preceded by 'except ... as var:'
        pattern1 = re.compile(
            r'(except\s+[^:]+\s+as\s+(\w+):[^}]*?)'  # capture exception block with variable name
            r'(\s+raise\s+\w+\([^)]*\))\s*$',  # capture raise statement
            re.MULTILINE
        )

        def replace_func1(match):
            block_content = match.group(1)
            var_name = match.group(2)
            raise_statement = match.group(3)
            # Add ' from {var_name}' to the raise statement if it doesn't already have it
            if ' from ' not in raise_statement:
                return block_content + raise_statement + f' from {var_name}'
            return match.group(0)

        content = pattern1.sub(replace_func1, content)

        # Pattern 2: Multi-line raise statements
        pattern2 = re.compile(
            r'(except\s+[^:]+\s+as\s+(\w+):[^}]*?)'  # capture exception block with variable name
            r'(\s+raise\s+\w+\(\s*[^)]*?\s*\))\s*$',  # capture multi-line raise statement
            re.MULTILINE | re.DOTALL
        )

        def replace_func2(match):
            block_content = match.group(1)
            var_name = match.group(2)
            raise_statement = match.group(3)
            # Add ' from {var_name}' to the raise statement if it doesn't already have it
            if ' from ' not in raise_statement:
                return block_content + raise_statement + f' from {var_name}'
            return match.group(0)

        content = pattern2.sub(replace_func2, content)

        # Pattern 3: Handle cases where we should use 'from None' instead
        # For ImportError cases where we want to suppress the original exception
        content = re.sub(
            r'(except\s+ImportError[^:]*:[^}]*?)'
            r'(\s+raise\s+RuntimeError\([^)]*\)) from \w+',
            r'\1\2 from None',
            content,
            flags=re.MULTILINE | re.DOTALL
        )

        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to fix B904 issues."""
    base_dir = "C:\\Intellicrack\\intellicrack"
    files_fixed = 0

    # Walk through all Python files
    for root, _dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                if fix_file_b904_issues(file_path):
                    print(f"Fixed: {file_path}")
                    files_fixed += 1

    print(f"Fixed {files_fixed} files")

if __name__ == "__main__":
    main()
