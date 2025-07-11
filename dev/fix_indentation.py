#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""Quick script to fix the critical indentation issues in main_app.py"""

import re

# Read the file
with open('intellicrack/ui/main_app.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')

# Fix the helper functions that need their bodies indented
helper_functions = [
    '_generate_network_report_section',
    '_generate_patching_report_section',
    '_generate_general_report_section',
    '_format_memory_analysis_for_text',
    '_format_network_analysis_for_text',
    '_format_patching_results_for_text'
]

# Track which functions we're inside
inside_function = None
function_start_line = None

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]

    # Check if we're starting one of the helper functions
    for func_name in helper_functions:
        if line.strip().startswith(f'def {func_name}(self):'):
            inside_function = func_name
            function_start_line = i
            new_lines.append(line)
            i += 1
            break
    else:
        # Check if we're ending a function (next function or end of file)
        if inside_function and (line.strip().startswith('def ') or line.strip().startswith('class ') or i == len(lines) - 1):
            inside_function = None
            function_start_line = None
            new_lines.append(line)
            i += 1
        elif inside_function:
            # We're inside a helper function - fix indentation
            if line.strip() == '':
                # Empty line, keep as is
                new_lines.append(line)
            elif line.startswith('    '):
                # Already has some indentation, ensure it's at least 8 spaces for class method
                if not line.startswith('        '):
                    # Add 4 more spaces
                    new_lines.append('    ' + line)
                else:
                    new_lines.append(line)
            else:
                # No indentation, add 8 spaces for class method body
                new_lines.append('        ' + line)
            i += 1
        else:
            # Not inside a helper function, keep line as is
            new_lines.append(line)
            i += 1

# Write the fixed content back
with open('intellicrack/ui/main_app.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines))

print("Fixed indentation for helper functions")
