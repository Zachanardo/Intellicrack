#!/usr/bin/env python3
"""Validate darglint fixes for success_rate_analyzer.py."""

import subprocess
import sys
from pathlib import Path


if __name__ == "__main__":
    target = Path("D:/Intellicrack/intellicrack/plugins/custom_modules/success_rate_analyzer.py")
    if not target.exists():
        print(f"ERROR: File not found: {target}")
        sys.exit(1)
    print(f"Running darglint on {target}...")
    result = subprocess.run(
        ["pixi", "run", "darglint", str(target)],
        capture_output=True,
        text=True,
        cwd="D:/Intellicrack",
    )
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    print(f"\nReturn code: {result.returncode}")
    if result.returncode == 0:
        print("\nSUCCESS: No darglint violations found!")
    else:
        print("\nFAILURE: Darglint found violations")
    sys.exit(result.returncode)
