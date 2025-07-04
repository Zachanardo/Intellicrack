#!/usr/bin/env python3
"""
Update PE resources using rcedit
"""

import os
import subprocess
import sys

def update_resources(exe_file):
    """Update icon and version info for executable"""

    if not os.path.exists(exe_file):
        print(f"File not found: {exe_file}")
        return False

    print(f"Updating resources for {exe_file}...")

    # Update icon
    if os.path.exists("icp_engine.ico"):
        cmd = ["./rcedit.exe", exe_file, "--set-icon", "icp_engine.ico"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("  - Icon updated")
        else:
            print(f"  - Icon update failed: {result.stderr}")

    # Update version info
    version_updates = [
        ("--set-version-string", "CompanyName", "Intellicrack"),
        ("--set-version-string", "FileDescription", "ICP Engine - Intellicrack Protection Engine"),
        ("--set-version-string", "FileVersion", "1.0.0.0"),
        ("--set-version-string", "InternalName", "ICP Engine"),
        ("--set-version-string", "LegalCopyright", "Copyright (C) 2025 Intellicrack"),
        ("--set-version-string", "OriginalFilename", exe_file),
        ("--set-version-string", "ProductName", "ICP Engine"),
        ("--set-version-string", "ProductVersion", "1.0.0.0"),
        ("--set-file-version", "1.0.0.0"),
        ("--set-product-version", "1.0.0.0"),
    ]

    for args in version_updates:
        cmd = ["./rcedit.exe", exe_file] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  - Failed to set {args[1]}: {result.stderr}")

    print(f"  - Version info updated")
    return True

def main():
    files = ["icp-gui.exe", "icp-engine.exe", "icp-lite.exe"]

    for exe_file in files:
        if os.path.exists(exe_file):
            update_resources(exe_file)
        else:
            print(f"Skipping {exe_file} - not found")

    print("\nResource update complete!")

if __name__ == "__main__":
    main()