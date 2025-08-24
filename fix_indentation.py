"""Fix indentation issues in vulnerability_research_dialog.py"""
import re


def fix_indentation():
    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    fixed_lines = []
    current_indent = 0
    in_class = False
    in_method = False
    in_nested_class = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip empty lines
        if not stripped:
            fixed_lines.append(line)
            continue

        # Class definition
        if re.match(r'^class\s+\w+', stripped):
            if 'VulnerabilityResearchDialog' in stripped:
                in_class = True
                current_indent = 0
                fixed_lines.append(line.lstrip())
            else:
                # Nested class
                in_nested_class = True
                fixed_lines.append('    ' + stripped + '\n')
            continue

        # Method definition
        if re.match(r'^def\s+', stripped):
            if in_nested_class:
                # Method in nested class
                fixed_lines.append('        ' + stripped + '\n')
                in_method = True
                current_indent = 12
            elif in_class:
                # Method in main class
                fixed_lines.append('    ' + stripped + '\n')
                in_method = True
                current_indent = 8
            else:
                # Module level function
                fixed_lines.append(stripped + '\n')
                in_method = True
                current_indent = 4
            continue

        # Docstrings
        if stripped.startswith('"""'):
            if in_method:
                fixed_lines.append(' ' * current_indent + stripped + '\n')
            else:
                fixed_lines.append(line)
            continue

        # Regular code lines
        if in_method:
            # Remove existing indentation and add correct one
            fixed_lines.append(' ' * current_indent + stripped + '\n')
        else:
            fixed_lines.append(line)

        # Check if we're exiting a structure
        if stripped.startswith('return ') or stripped == 'pass':
            # Check next non-empty line
            for j in range(i+1, min(i+5, len(lines))):
                next_stripped = lines[j].strip()
                if next_stripped:
                    if re.match(r'^def\s+', next_stripped) or re.match(r'^class\s+', next_stripped):
                        in_method = False
                        current_indent = 0
                    break

    with open('intellicrack/ui/dialogs/vulnerability_research_dialog.py', 'w', encoding='utf-8') as f:
        f.writelines(fixed_lines)

    print("Fixed indentation")

if __name__ == "__main__":
    fix_indentation()
