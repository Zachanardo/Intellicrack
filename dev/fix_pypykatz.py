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
import shutil
import site

# Get site-packages directory
site_packages = site.getsitepackages()[0]
print(f"Site packages: {site_packages}")

# Look for pypykatz related directories
pypykatz_dirs = []
for item in os.listdir(site_packages):
    if 'pypykatz' in item.lower():
        full_path = os.path.join(site_packages, item)
        pypykatz_dirs.append(full_path)
        print(f"Found: {full_path}")

# Remove them
for dir_path in pypykatz_dirs:
    try:
        if os.path.isdir(dir_path):
            shutil.rmtree(dir_path)
            print(f"Removed directory: {dir_path}")
        else:
            os.remove(dir_path)
            print(f"Removed file: {dir_path}")
    except Exception as e:
        print(f"Error removing {dir_path}: {e}")

# Check Scripts folder
scripts_dir = os.path.join(os.path.dirname(site_packages), "Scripts")
if os.path.exists(scripts_dir):
    for item in os.listdir(scripts_dir):
        if 'pypykatz' in item.lower():
            try:
                full_path = os.path.join(scripts_dir, item)
                os.remove(full_path)
                print(f"Removed script: {full_path}")
            except Exception as e:
                print(f"Error removing script: {e}")

print("\nCleanup complete. Now run: pip install pypykatz==0.6.11")