#!/usr/bin/env python3
"""Quick script to run mypy on the test file and show results."""

import subprocess
import sys

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "mypy",
        "--strict",
        "tests/core/network/test_generic_protocol_handler_comprehensive.py",
    ],
    capture_output=True,
    text=True,
)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")

sys.exit(result.returncode)
