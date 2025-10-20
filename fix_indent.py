#!/usr/bin/env python3
"""Fix docstring indentation in subscription_validation_bypass.py"""

from pathlib import Path

TARGET_FILE = Path("intellicrack/core/subscription_validation_bypass.py")

def fix_indentation():
    """Fix docstrings that need one more level of indentation."""
    lines = TARGET_FILE.read_text(encoding='utf-8').split('\n')
    result = []
    i = 0

    while i < len(lines):
        line = lines[i]
        result.append(line)

        # Check if this line is a method def ending with ):
        if line.strip().startswith('def ') and line.rstrip().endswith('):'):
            # Check if next line is a docstring at the same indentation level
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                if next_line.lstrip().startswith('"""'):
                    # Get indentation levels
                    def_indent = len(line) - len(line.lstrip())
                    doc_indent = len(next_line) - len(next_line.lstrip())

                    # If docstring has same indent as def, it needs more indent
                    if doc_indent == def_indent and doc_indent > 0:
                        # Fix the docstring and all continuation lines
                        i += 1
                        while i < len(lines):
                            doc_line = lines[i]
                            # Add 4 spaces if line is not empty
                            if doc_line.strip():
                                result.append('    ' + doc_line)
                            else:
                                result.append(doc_line)

                            # Check if this is the end of docstring
                            if '"""' in doc_line and doc_line.strip() != '"""':
                                if doc_line.count('"""') >= 2 or (doc_line.count('"""') == 1 and not result[-2].strip().startswith('"""')):
                                    i += 1
                                    break
                            elif doc_line.strip() == '"""':
                                i += 1
                                break

                            i += 1
                        continue

        i += 1

    TARGET_FILE.write_text('\n'.join(result), encoding='utf-8')
    print(f"✅ Fixed docstring indentation in {TARGET_FILE}")

if __name__ == "__main__":
    fix_indentation()
