#!/usr/bin/env python3
"""
ICP Engine Rebranding Script
Replaces DIE references with ICP Engine branding
"""

import os
import shutil
import sys


def backup_file(filepath):
    """Create a backup of the file"""
    backup_path = filepath + ".bak"
    if not os.path.exists(backup_path):
        shutil.copy2(filepath, backup_path)
        print(f"Backup created: {backup_path}")
    return backup_path


def patch_binary(filepath, replacements):
    """Patch binary with string replacements"""
    # Read the entire file
    with open(filepath, 'rb') as f:
        data = f.read()

    modified = False
    for old_str, new_str in replacements:
        # Convert strings to bytes
        old_bytes = old_str.encode('utf-8')
        new_bytes = new_str.encode('utf-8')

        # Ensure new string is not longer than old
        if len(new_bytes) > len(old_bytes):
            print(f"Warning: '{new_str}' is longer than '{old_str}' - padding old string")
            continue

        # Pad new string with nulls if shorter
        if len(new_bytes) < len(old_bytes):
            new_bytes = new_bytes + b'\x00' * (len(old_bytes) - len(new_bytes))

        # Count occurrences
        count = data.count(old_bytes)
        if count > 0:
            print(f"Found {count} occurrences of '{old_str}'")
            data = data.replace(old_bytes, new_bytes)
            modified = True

    # Write back if modified
    if modified:
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"Patched: {filepath}")
    else:
        print(f"No changes needed for: {filepath}")

    return modified


def main():
    # Define string replacements
    replacements = [
        ("Detect It Easy", "ICP Engine"),
        ("Detect-It-Easy", "ICP Engine"),
        ("https://github.com/horsicq/Detect-It-Easy", "https://intellicrack.com/icp"),
        ("Copyright(C) 2006-2008 Hellsp@wn 2012-2025 hors<horsicq@gmail.com>", "Copyright(C) 2025 Intellicrack Team"),
        ("Web: http://ntinfo.biz", "Web: intellicrack.com"),
        ("die\x00", "icp\x00"),
        ("DIE(Detect It Easy)", "ICP Engine"),
    ]

    # Files to patch
    files = [
        "icp-gui.exe",
        "icp-engine.exe",
        "icp-lite.exe"
    ]

    for filename in files:
        if os.path.exists(filename):
            print(f"\nProcessing {filename}...")
            backup_file(filename)
            patch_binary(filename, replacements)
        else:
            print(f"File not found: {filename}")

    print("\nRebranding complete!")
    print("Note: For complete rebranding including icons and version info,")
    print("use Resource Hacker or rebuild from source.")


if __name__ == "__main__":
    main()