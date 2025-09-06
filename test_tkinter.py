#!/usr/bin/env python3

import os
import sys

print(f"Python executable: {sys.executable}")
print(f"Current directory: {os.getcwd()}")
print(f"PATH: {os.environ.get('PATH', 'NOT SET')[:200]}...")
print(f"TCL_LIBRARY: {os.environ.get('TCL_LIBRARY', 'NOT SET')}")
print(f"TK_LIBRARY: {os.environ.get('TK_LIBRARY', 'NOT SET')}")

try:
    import _tkinter
    print("✅ SUCCESS: _tkinter imported successfully")
    
    # Try creating a simple tkinter window
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # Hide the window
        root.destroy()
        print("✅ SUCCESS: tkinter GUI created and destroyed")
    except Exception as e:
        print(f"❌ FAIL: tkinter GUI creation failed: {e}")
        
except ImportError as e:
    print(f"❌ FAIL: _tkinter import failed: {e}")
except Exception as e:
    print(f"❌ FAIL: Unexpected error: {e}")