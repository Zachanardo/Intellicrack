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
Comprehensive pylint E-level error scanner for Intellicrack
"""
import os
import subprocess
import sys
from pathlib import Path


def run_pylint_on_file(file_path, venv_path):
    """Run pylint on a single file and return E-level errors"""
    cmd = [
        f"{venv_path}/bin/pylint",
        "--errors-only",
        "--msg-template={path}:{line}: [{msg_id}({symbol})] {msg}",
        str(file_path)
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"{file_path}: TIMEOUT\n"
    except Exception as e:
        return f"{file_path}: ERROR - {e}\n"


def main():
    # Find all Python files in intellicrack directory
    intellicrack_path = Path("intellicrack")
    if not intellicrack_path.exists():
        print("Error: intellicrack directory not found")
        return 1

    venv_path = Path(".zen_venv")
    if not venv_path.exists():
        print("Error: .zen_venv directory not found")
        return 1

    python_files = list(intellicrack_path.rglob("*.py"))
    print(f"Found {len(python_files)} Python files to scan")

    all_errors = []
    import_errors = []
    syntax_errors = []
    other_errors = []

    for i, file_path in enumerate(python_files):
        print(f"Scanning {i+1}/{len(python_files)}: {file_path}")

        output = run_pylint_on_file(file_path, venv_path)

        for line in output.strip().split('\n'):
            if line and ': [E' in line:
                all_errors.append(line)

                # Categorize errors
                if '[E0401(' in line:  # import-error
                    import_errors.append(line)
                elif '[E0001(' in line or '[E1101(' in line:  # syntax errors / no-member
                    syntax_errors.append(line)
                else:
                    other_errors.append(line)

    # Write results
    with open("pylint_e_level_errors.txt", "w") as f:
        f.write("COMPREHENSIVE PYLINT E-LEVEL ERROR SCAN\n")
        f.write("=" * 50 + "\n\n")

        f.write(f"SUMMARY:\n")
        f.write(f"Total E-level errors found: {len(all_errors)}\n")
        f.write(f"Import errors (E0401): {len(import_errors)}\n")
        f.write(f"Syntax/Member errors: {len(syntax_errors)}\n")
        f.write(f"Other E-level errors: {len(other_errors)}\n\n")

        f.write("ALL E-LEVEL ERRORS:\n")
        f.write("-" * 30 + "\n")
        for error in sorted(all_errors):
            f.write(error + "\n")

        f.write("\n\nIMPORT ERRORS (E0401):\n")
        f.write("-" * 30 + "\n")
        for error in sorted(import_errors):
            f.write(error + "\n")

        f.write("\n\nSYNTAX/MEMBER ERRORS:\n")
        f.write("-" * 30 + "\n")
        for error in sorted(syntax_errors):
            f.write(error + "\n")

        f.write("\n\nOTHER E-LEVEL ERRORS:\n")
        f.write("-" * 30 + "\n")
        for error in sorted(other_errors):
            f.write(error + "\n")

    print(f"\nScan complete!")
    print(f"Total E-level errors found: {len(all_errors)}")
    print(f"Results saved to: pylint_e_level_errors.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())
