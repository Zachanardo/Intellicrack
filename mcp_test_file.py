#!/usr/bin/env python3
"""Validate darglint fixes for success_rate_analyzer.py."""

import subprocess
from pathlib import Path


if __name__ == "__main__":
    target = Path("D:/Intellicrack/intellicrack/plugins/custom_modules/success_rate_analyzer.py")
    if not target.exists():
        print(f"ERROR: File not found: {target}")
        exit(1)
    print(f"Running darglint on {target}...")
    result = subprocess.run(
        ["pixi", "run", "darglint", str(target)],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    print(f"Return code: {result.returncode}")
    if result.returncode == 0:
        print("SUCCESS: No darglint violations found!")
    else:
        print("FAILURE: Darglint found violations")
    exit(result.returncode)
