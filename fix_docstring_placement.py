#!/usr/bin/env python3
"""Fix misplaced docstrings in subscription_validation_bypass.py"""

import re
from pathlib import Path

TARGET_FILE = Path("intellicrack/core/subscription_validation_bypass.py")

def fix_docstrings():
    """Fix all docstrings that are misplaced in multi-line function signatures."""
    content = TARGET_FILE.read_text(encoding='utf-8')

    # Pattern: method signature without closing paren, followed by docstring, then params
    # Match: def method_name(\n    """docstring"""
    pattern = r'(    def \w+\([^)]*\):)\n(\s+"""[^"]*(?:""")?[^"]*)"""(\s+)(.*?)(\n\s+def |\n\nclass )'

    def replacement(match):
        # Get the parts
        sig_part = match.group(1)  # def method_name():
        docstring_start = match.group(2)  # """docstring content
        indent = match.group(3)
        rest = match.group(4)
        next_thing = match.group(5)

        # Reconstruct with docstring after signature
        return f'{sig_part}\n{indent}"""{docstring_start}"""\n{rest}{next_thing}'

    # This simpler approach: find lines where docstring comes right after method def
    # without proper indentation
    lines = content.split('\n')
    result_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]

        # Check if this is a method definition line ending with ):
        if re.match(r'^\s+def \w+\([^)]*\):$', line):
            # Check if next line is a docstring without proper indentation
            if i + 1 < len(lines) and lines[i+1].strip().startswith('"""'):
                # This is a properly placed docstring, keep as is
                result_lines.append(line)
                i += 1
                continue
            # Check if next line is a docstring but misaligned (same indent as def)
            elif i + 1 < len(lines) and re.match(r'^    """', lines[i+1]):
                # Check the indentation
                method_indent = len(line) - len(line.lstrip())
                docstring_indent = len(lines[i+1]) - len(lines[i+1].lstrip())

                if docstring_indent == method_indent:
                    # Misplaced docstring - needs one more level of indent
                    result_lines.append(line)
                    # Re-indent the docstring
                    docstring_lines = []
                    i += 1
                    while i < len(lines) and ('"""' in lines[i] or not lines[i].strip().startswith('def')):
                        # Add extra indent
                        if lines[i].strip():
                            result_lines.append('    ' + lines[i])
                        else:
                            result_lines.append(lines[i])
                        if '"""' in lines[i] and lines[i].strip() != '"""' and lines[i].count('"""') == 1:
                            # This is end of docstring
                            i += 1
                            break
                        elif lines[i].strip().endswith('"""') and lines[i].count('"""') == 2:
                            # Single line docstring
                            i += 1
                            break
                        elif lines[i].strip() == '"""':
                            # Closing docstring
                            i += 1
                            break
                        i += 1
                    continue

        result_lines.append(line)
        i += 1

    TARGET_FILE.write_text('\n'.join(result_lines), encoding='utf-8')
    print(f"✅ Fixed docstring placement in {TARGET_FILE}")

if __name__ == "__main__":
    fix_docstrings()
