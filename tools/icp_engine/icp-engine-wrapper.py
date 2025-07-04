#!/usr/bin/env python3
"""
ICP Engine wrapper that ensures consistent branding across all output
Part of the Intellicrack Protection Engine system
"""
import os
import subprocess
import sys


def main():
    # Get the real engine path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    real_engine = os.path.join(script_dir, "icp-engine.exe")

    # Run the real engine with all arguments
    proc = subprocess.Popen(
        [real_engine] + sys.argv[1:],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    stdout, stderr = proc.communicate()

    # Replace DIE references in output
    replacements = [
        ("die ", "icp-engine "),
        ("DIE ", "ICP Engine "),
        ("Detect It Easy", "Intellicrack Protection Engine"),
        ("Detect-It-Easy", "Intellicrack Protection Engine"),
        ("DIE(Detect It Easy)", "Intellicrack Protection Engine"),
        ("die_version", "engine_version"),
    ]

    for old, new in replacements:
        stdout = stdout.replace(old, new)
        stderr = stderr.replace(old, new)

    # Output the modified text
    if stdout:
        print(stdout, end='')
    if stderr:
        print(stderr, end='', file=sys.stderr)

    return proc.returncode

if __name__ == "__main__":
    sys.exit(main())
