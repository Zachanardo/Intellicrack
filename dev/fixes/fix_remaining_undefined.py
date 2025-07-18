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

"""Fix remaining undefined variable references"""

import re

file_path = '/mnt/c/Intellicrack/intellicrack/core/processing/distributed_analysis_manager.py'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix all occurrences of vm[ and container[ that should be _vm[ and _container[
# within for loops
lines = content.split('\n')
new_lines = []
in_vm_loop = False
in_container_loop = False

for i, line in enumerate(lines):
    # Check for loop starts
    if 'for _vm in self.vms:' in line:
        in_vm_loop = True
        in_container_loop = False
    elif 'for _container in self.containers:' in line:
        in_container_loop = True
        in_vm_loop = False
    elif line.strip() and not line.startswith(' ') and not line.startswith('\t'):
        # Reset on new method/class
        in_vm_loop = False
        in_container_loop = False

    # Replace within loops
    if in_vm_loop and re.search(r'\bvm\[', line):
        line = re.sub(r'\bvm\[', '_vm[', line)
    if in_container_loop and re.search(r'\bcontainer\[', line):
        line = re.sub(r'\bcontainer\[', '_container[', line)

    new_lines.append(line)

# Also fix specific issues in get_status and other methods
content = '\n'.join(new_lines)

# Fix variables in list comprehensions
content = re.sub(r'for _vm in self\.vms\s*\]', 'for vm in self.vms]', content)
content = re.sub(r'for _container in self\.containers\s*\]',
                 'for container in self.containers]', content)

# Fix references in summary
content = re.sub(r'running_vms = \[vm for _vm',
                 'running_vms = [_vm for _vm', content)
content = re.sub(
    r'running_containers = \[c for _c', 'running_containers = [_c for _c', content)

# Write back
with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed remaining undefined variable references")
