#!/usr/bin/env python3
"""Quick syntax validation for frida_protection_bypass.py."""

import sys

try:
    import py_compile
    py_compile.compile(
        "intellicrack/core/analysis/frida_protection_bypass.py",
        doraise=True
    )
    print("✅ Python syntax is valid")
    sys.exit(0)
except py_compile.PyCompileError as e:
    print(f"❌ Syntax error: {e}")
    sys.exit(1)
