#!/usr/bin/env python
"""Test if capstone is causing the hang."""

print("Testing capstone import...")

try:
    print("\n1. Importing capstone...")
    import capstone
    print("   OK Capstone imported successfully")
    print(f"   Version: {capstone.cs_version()}")

    print("\nOK Capstone works fine!")

except Exception as e:
    import traceback
    print(f"\nFAIL Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
