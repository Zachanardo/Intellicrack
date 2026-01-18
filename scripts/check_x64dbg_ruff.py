#!/usr/bin/env python3
"""Check ruff on x64dbg.py."""

import subprocess
import sys

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "ruff",
        "check",
        "src/intellicrack/bridges/x64dbg.py",
        "--output-format=concise",
    ],
    cwd=r"D:\Intellicrack",
    capture_output=True,
    text=True,
)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")
