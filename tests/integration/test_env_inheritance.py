#!/usr/bin/env python3
"""Test environment variable inheritance."""
import os
import sys

print("=== Environment Variable Test ===", file=sys.stderr)
print(f"TCL_LIBRARY: {os.environ.get('TCL_LIBRARY', 'NOT SET')}", file=sys.stderr)
print(f"TK_LIBRARY: {os.environ.get('TK_LIBRARY', 'NOT SET')}", file=sys.stderr)

# Try to import _tkinter
try:
    import _tkinter
    print("✅ _tkinter imported successfully", file=sys.stderr)

    # Try to create a GUI
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        print("✅ tkinter GUI creation successful", file=sys.stderr)
    except Exception as e:
        print(f"❌ tkinter GUI creation failed: {e}", file=sys.stderr)

except Exception as e:
    print(f"❌ _tkinter import failed: {e}", file=sys.stderr)
