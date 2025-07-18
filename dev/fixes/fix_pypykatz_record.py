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

import os
import site

# Get site-packages directory
site_packages = site.getsitepackages()[0]

# Find any pypykatz dist-info directory
dist_info_dir = None
for item in os.listdir(site_packages):
    if 'pypykatz' in item and 'dist-info' in item:
        dist_info_dir = os.path.join(site_packages, item)
        break

if dist_info_dir:
    # Create a minimal RECORD file
    record_path = os.path.join(dist_info_dir, 'RECORD')
    with open(record_path, 'w') as f:
        f.write('pypykatz/__init__.py,,\n')
    print(f"Created RECORD file at: {record_path}")
else:
    # Create the dist-info directory and RECORD file
    dist_info_dir = os.path.join(site_packages, 'pypykatz-0.6.11.dist-info')
    os.makedirs(dist_info_dir, exist_ok=True)

    # Create minimal metadata
    metadata_path = os.path.join(dist_info_dir, 'METADATA')
    with open(metadata_path, 'w') as f:
        f.write('Metadata-Version: 2.1\nName: pypykatz\nVersion: 0.6.11\n')

    # Create RECORD file
    record_path = os.path.join(dist_info_dir, 'RECORD')
    with open(record_path, 'w') as f:
        f.write('pypykatz/__init__.py,,\n')

    print(f"Created dist-info directory and RECORD file at: {dist_info_dir}")

print("Now try: pip uninstall pypykatz -y")
