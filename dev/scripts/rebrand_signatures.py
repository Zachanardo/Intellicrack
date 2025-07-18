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
Rebrand DIE signature files to Intellicrack Protection Engine
"""

import os
import re
from pathlib import Path


def rebrand_signature_file(file_path):
    """Rebrand a single signature file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Replace various forms of DIE references
        replacements = [
            (r"Detect It Easy", "Intellicrack Protection Engine"),
            (r"DIE detection", "Intellicrack protection detection"),
            (r"DIE:", "ICP:"),
            (r"// DIE", "// ICP"),
            (r"# DIE", "# ICP"),
        ]

        modified = False
        for pattern, replacement in replacements:
            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                modified = True
                content = new_content

        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False


def main():
    signatures_dir = Path("/mnt/c/Intellicrack/tools/icp_engine/signatures")

    if not signatures_dir.exists():
        print(f"Signatures directory not found: {signatures_dir}")
        return

    total_files = 0
    modified_files = 0

    # Process all .ics files
    for file_path in signatures_dir.rglob("*.ics"):
        total_files += 1
        if rebrand_signature_file(file_path):
            modified_files += 1
            print(f"Modified: {file_path.relative_to(signatures_dir)}")

    print(f"\nRebranding complete!")
    print(f"Total files processed: {total_files}")
    print(f"Files modified: {modified_files}")


if __name__ == "__main__":
    main()
