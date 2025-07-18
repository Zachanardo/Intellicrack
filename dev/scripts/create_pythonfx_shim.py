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

"""
Create a fake python-fx package to satisfy qiling without conflicts
"""
import os
import site

def create_fake_pythonfx():
    """Create a minimal python-fx shim"""
    site_packages = site.getsitepackages()[0]
    pythonfx_dir = os.path.join(site_packages, "python_fx")
    os.makedirs(pythonfx_dir, exist_ok=True)

    # Create minimal __init__.py
    init_content = '''"""
Minimal python-fx compatibility shim for qiling
"""

class Fx:
    def __init__(self):
        pass

    def __call__(self, *args, **kwargs):
        # Minimal implementation - just return the first argument
        if args:
            return args[0]
        return None

# Create default instance
fx = Fx()

# Common functions that might be used
def apply(func, *args):
    return func(*args) if callable(func) else func

def pipe(*functions):
    def _pipe(value):
        for func in functions:
            value = func(value) if callable(func) else value
        return value
    return _pipe
'''

    init_path = os.path.join(pythonfx_dir, "__init__.py")
    with open(init_path, 'w') as f:
        f.write(init_content)

    # Create dist-info
    dist_info_dir = os.path.join(site_packages, "python_fx-0.3.2.dist-info")
    os.makedirs(dist_info_dir, exist_ok=True)

    metadata = '''Metadata-Version: 2.1
Name: python-fx
Version: 0.3.2
Summary: Fake python-fx for compatibility
'''

    with open(os.path.join(dist_info_dir, "METADATA"), 'w') as f:
        f.write(metadata)

    with open(os.path.join(dist_info_dir, "top_level.txt"), 'w') as f:
        f.write("python_fx\n")

    print(f"✓ Created fake python-fx at {pythonfx_dir}")

if __name__ == "__main__":
    # First uninstall the problematic python-fx
    import subprocess
    import sys

    try:
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "python-fx", "-y"], check=True)
        print("✓ Uninstalled python-fx")
    except:
        print("python-fx not installed")

    create_fake_pythonfx()

    # Test qiling import
    try:
        import qiling
        print("✓ qiling imports with fake python-fx")
    except Exception as e:
        print(f"✗ qiling import failed: {e}")
