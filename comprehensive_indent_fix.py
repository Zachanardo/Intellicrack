#!/usr/bin/env python3
"""Comprehensive indentation fix by identifying and fixing patterns."""

import re


def fix_all_indentation():
    """Fix all indentation issues comprehensively."""

    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    fixed_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Empty lines - keep as is
        if not stripped:
            fixed_lines.append(line)
            i += 1
            continue

        # Check if this is a function/method definition
        if re.match(r'def\s+\w+\(', stripped):
            # Determine correct indentation based on context
            if 'self' in line or 'cls' in line:
                # Class method - should be indented
                # Check if we're in a nested class or main class
                indent_level = 4  # Default for main class methods

                # Look back to see if we're in a nested class
                for j in range(i-1, max(0, i-50), -1):
                    if 'class ' in lines[j]:
                        if lines[j].strip().startswith('class '):
                            # Check indentation of the class
                            class_indent = len(lines[j]) - len(lines[j].lstrip())
                            if class_indent > 0:
                                indent_level = 8  # Nested class method
                            break

                fixed_lines.append(' ' * indent_level + stripped + '\n')
            else:
                # Module-level function
                fixed_lines.append(stripped + '\n')

            i += 1

            # Handle docstring if present
            if i < len(lines) and lines[i].strip().startswith('"""'):
                # Docstring should be indented relative to the function
                func_indent = len(fixed_lines[-1]) - len(fixed_lines[-1].lstrip())
                fixed_lines.append(' ' * (func_indent + 4) + lines[i].strip() + '\n')
                i += 1

            # Handle the rest of the function body
            while i < len(lines):
                curr_line = lines[i]
                curr_stripped = curr_line.strip()

                if not curr_stripped:
                    fixed_lines.append(curr_line)
                    i += 1
                    continue

                # Check if we've reached another function/class
                if re.match(r'(def|class)\s+\w+', curr_stripped):
                    break

                # Handle try blocks specially
                if curr_stripped == 'try:':
                    func_indent = len(fixed_lines[-2]) - len(fixed_lines[-2].lstrip()) if len(fixed_lines) >= 2 else 0
                    if 'def ' in fixed_lines[-2] if len(fixed_lines) >= 2 else False:
                        func_indent = len(fixed_lines[-2]) - len(fixed_lines[-2].lstrip())
                    fixed_lines.append(' ' * (func_indent + 4) + 'try:\n')
                    i += 1
                    continue

                # Handle except/finally blocks
                if curr_stripped.startswith(('except', 'finally')):
                    # Find the matching try
                    try_indent = 0
                    for j in range(len(fixed_lines)-1, max(0, len(fixed_lines)-20), -1):
                        if fixed_lines[j].strip() == 'try:':
                            try_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip())
                            break
                    fixed_lines.append(' ' * try_indent + curr_stripped + '\n')
                    i += 1
                    continue

                # Handle if/elif/else
                if curr_stripped.startswith(('if ', 'elif ', 'else:')):
                    # Determine indentation based on context
                    base_indent = 8  # Default for method body

                    # Look back for context
                    for j in range(len(fixed_lines)-1, max(0, len(fixed_lines)-10), -1):
                        if 'def ' in fixed_lines[j]:
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            break
                        elif fixed_lines[j].strip().startswith(('try:', 'except', 'finally')):
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            break

                    fixed_lines.append(' ' * base_indent + curr_stripped + '\n')
                    i += 1
                    continue

                # Handle return statements
                if curr_stripped.startswith('return '):
                    # Determine indentation based on context
                    base_indent = 8  # Default for method body

                    # Look back for context
                    for j in range(len(fixed_lines)-1, max(0, len(fixed_lines)-10), -1):
                        if 'def ' in fixed_lines[j]:
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            break
                        elif fixed_lines[j].strip().startswith(('if ', 'elif ', 'else:', 'try:', 'except', 'finally', 'with ', 'for ', 'while ')):
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            break

                    fixed_lines.append(' ' * base_indent + curr_stripped + '\n')
                    i += 1
                    continue

                # Handle import statements
                if curr_stripped.startswith(('import ', 'from ')):
                    # Determine indentation based on context
                    base_indent = 0  # Default for module level

                    # Check if we're inside a try block
                    for j in range(len(fixed_lines)-1, max(0, len(fixed_lines)-5), -1):
                        if fixed_lines[j].strip() == 'try:':
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            break

                    fixed_lines.append(' ' * base_indent + curr_stripped + '\n')
                    i += 1
                    continue

                # Default - maintain relative indentation to function
                if len(fixed_lines) > 1:
                    for j in range(len(fixed_lines)-1, max(0, len(fixed_lines)-20), -1):
                        if 'def ' in fixed_lines[j]:
                            base_indent = len(fixed_lines[j]) - len(fixed_lines[j].lstrip()) + 4
                            fixed_lines.append(' ' * base_indent + curr_stripped + '\n')
                            break
                    else:
                        fixed_lines.append(curr_line)
                else:
                    fixed_lines.append(curr_line)

                i += 1

        else:
            # Not a function definition - handle other cases
            fixed_lines.append(line)
            i += 1

    # Write the fixed content
    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)

    print("Comprehensively fixed indentation")

if __name__ == "__main__":
    fix_all_indentation()
