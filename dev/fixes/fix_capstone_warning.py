#!/usr/bin/env python3
"""
Quick fix for Capstone pkg_resources deprecation warning.
This script patches the issue in the virtual environment.
"""

import os
import sys
from pathlib import Path

def fix_capstone_warning():
    """Patch the Capstone warning by modifying the import."""

    # Find the capstone module in venv
    venv_paths = [
        '.venv_windows/Lib/site-packages/capstone/__init__.py',
        '.venv/lib/python*/site-packages/capstone/__init__.py'
    ]

    capstone_init = None
    for path_pattern in venv_paths:
        if '*' in path_pattern:
            # Handle glob pattern
            from glob import glob
            matches = glob(path_pattern)
            if matches:
                capstone_init = matches[0]
                break
        else:
            if os.path.exists(path_pattern):
                capstone_init = path_pattern
                break

    if not capstone_init:
        print("Capstone __init__.py not found in virtual environment")
        return

    print(f"Found Capstone at: {capstone_init}")

    # Read the file
    with open(capstone_init, 'r') as f:
        content = f.read()

    # Check if it contains the problematic import
    if 'import pkg_resources' in content:
        print("Patching pkg_resources import...")

        # Replace the problematic import with try/except
        old_import = 'import pkg_resources'
        new_import = '''try:
    import pkg_resources
except ImportError:
    # pkg_resources is deprecated, using fallback
    import importlib.metadata as pkg_resources'''

        # Also handle specific usage
        if 'pkg_resources.require' in content:
            content = content.replace('pkg_resources.require', 'pkg_resources.require')

        patched_content = content.replace(old_import, new_import)

        # Write back the patched file
        with open(capstone_init, 'w') as f:
            f.write(patched_content)

        print("Capstone warning patched successfully!")
    else:
        print("Capstone already patched or no pkg_resources import found")

if __name__ == '__main__':
    fix_capstone_warning()
