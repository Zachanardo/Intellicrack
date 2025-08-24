#!/usr/bin/env python3
"""Fix all try statement indentation issues."""

import re


def fix_try_indentation():
    """Fix all incorrectly indented try statements."""

    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    fixed_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]

        # Check if this is a method definition
        if re.match(r'^(\s*)def\s+\w+\(', line):
            fixed_lines.append(line)
            i += 1

            # Check if next non-empty line is a docstring
            while i < len(lines) and not lines[i].strip():
                fixed_lines.append(lines[i])
                i += 1

            if i < len(lines) and lines[i].strip().startswith('"""'):
                fixed_lines.append(lines[i])
                i += 1

                # Check next line - if it's a misaligned try, fix it
                while i < len(lines):
                    if lines[i].strip() == 'try:':
                        # This try should be indented properly for a method body
                        indent_match = re.match(r'^(\s*)def', lines[i-2] if i >= 2 else lines[i-1])
                        if indent_match:
                            base_indent = len(indent_match.group(1))
                            fixed_lines.append(' ' * (base_indent + 8) + 'try:\n')
                        else:
                            fixed_lines.append('        try:\n')
                        i += 1
                        break
                    elif lines[i].strip() and not lines[i].strip().startswith('"""'):
                        # Found non-try content after docstring
                        fixed_lines.append(lines[i])
                        i += 1
                        break
                    else:
                        fixed_lines.append(lines[i])
                        i += 1
            continue

        # Check for misaligned try statements
        if re.match(r'^(\s+)try:$', line):
            # Count the spaces
            spaces = len(line) - len(line.lstrip())

            # Check context to determine correct indentation
            # Look back for the containing structure
            containing_indent = 0
            for j in range(i-1, max(0, i-10), -1):
                if re.match(r'^(\s*)def\s+', lines[j]):
                    containing_indent = len(lines[j]) - len(lines[j].lstrip()) + 8
                    break
                elif re.match(r'^(\s*)(if|elif|else|for|while|with)\s', lines[j]):
                    containing_indent = len(lines[j]) - len(lines[j].lstrip()) + 4
                    break

            # If the try is not properly indented, fix it
            if spaces % 4 != 0 or spaces == containing_indent - 4:
                fixed_lines.append(' ' * containing_indent + 'try:\n')
            else:
                fixed_lines.append(line)
        else:
            fixed_lines.append(line)

        i += 1

    # Write the fixed content
    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)

    print("Fixed try statement indentation issues")

if __name__ == "__main__":
    fix_try_indentation()
