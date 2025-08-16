#!/usr/bin/env python
"""Test if capstone is causing the hang."""

print("Testing capstone import...")

try:
    print("\n1. Importing capstone...")
    import capstone
    print("   ✓ Capstone imported successfully")
    print(f"   Version: {capstone.cs_version()}")

    print("\n✅ Capstone works fine!")

except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
