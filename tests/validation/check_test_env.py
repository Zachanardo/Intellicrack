"""Check test environment and run minimal test."""

import sys
import os

print("Python executable:", sys.executable)
print("Python version:", sys.version)
print("Current directory:", os.getcwd())
print("\nPython path:")
for p in sys.path[:5]:
    print(f"  {p}")

print("\n" + "=" * 80)
print("Checking imports...")

try:
    import pytest
    print(f"OK pytest {pytest.__version__}")
except ImportError:
    print("FAIL pytest not found")

try:
    import coverage
    print(f"OK coverage {coverage.__version__}")
except ImportError:
    print("FAIL coverage not found")

try:
    from intellicrack.core.mitigation_bypass.cfi_bypass import CFIBypass
    print("OK CFIBypass import successful")

    # Test instantiation
    cfi = CFIBypass()
    print("OK CFIBypass instance created")

    # Check available methods
    methods = [m for m in dir(cfi) if not m.startswith('_')]
    print(f"\nPublic methods available: {len(methods)}")
    for method in methods[:5]:
        print(f"  - {method}")

except ImportError as e:
    print(f"FAIL CFIBypass import failed: {e}")
except Exception as e:
    print(f"FAIL Error creating instance: {e}")

print("\n" + "=" * 80)
print("Environment check complete.")
