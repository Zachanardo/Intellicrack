#!/usr/bin/env python3
"""Smart indentation fixer using autopep8."""

import subprocess
import sys


def fix_file():
    """Use autopep8 to fix indentation issues."""

    file_path = 'intellicrack/ui/dialogs/vulnerability_research_dialog.py'

    # Install autopep8 if not available
    try:
        import autopep8
    except ImportError:
        print("Installing autopep8...")
        subprocess.run([sys.executable, "-m", "pip", "install", "autopep8"], check=True)
        import autopep8

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    # Fix indentation and other issues
    fixed_code = autopep8.fix_code(code, options={
        'aggressive': 2,  # More aggressive fixing
        'max_line_length': 120,
        'indent_size': 4,
        'ignore': ['E501'],  # Ignore line too long
    })

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(fixed_code)

    print(f"Fixed indentation in {file_path}")

if __name__ == "__main__":
    fix_file()
