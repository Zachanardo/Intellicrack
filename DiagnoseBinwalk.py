"""Diagnostic script for testing binwalk3 functionality and backend availability."""

import subprocess
from pathlib import Path

import binwalk
from binwalk.core.module import Modules

print("=" * 70)
print("BINWALK3 DIAGNOSTIC")
print("=" * 70)

# Check 1: Version info
print("\n[1] VERSION INFO:")
print(f"  binwalk3 version: {binwalk.__version__}")
print(f"  API version: {binwalk.__api_version__}")

# Check 2: Backend availability
print("\n[2] BACKEND STATUS:")
backend = Modules().backend
print(f"  Backend available: {backend.available}")
print(f"  Binary path: {backend.binary_path}")

# Check 3: Binary exists
print("\n[3] BINARY FILE:")
binary_path = Path(backend.binary_path)
print(f"  Exists: {binary_path.exists()}")
if binary_path.exists():
    print(f"  Size: {binary_path.stat().st_size:,} bytes")
    print(f"  Location: {binary_path}")

# Check 4: Test binary directly
print("\n[4] BINARY EXECUTION TEST:")
try:
    result = subprocess.run([str(backend.binary_path), "--version"], capture_output=True, text=True, timeout=5)
    print(f"  Exit code: {result.returncode}")
    print(f"  Output: {result.stdout.strip()}")
    if result.stderr:
        print(f"  Errors: {result.stderr.strip()}")
except Exception as e:
    print(f"  ERROR: {e}")

# Check 5: Test binary with --help
print("\n[5] BINARY HELP (checking if it runs):")
try:
    result = subprocess.run([str(backend.binary_path), "--help"], capture_output=True, text=True, timeout=5)
    print(f"  Exit code: {result.returncode}")
    print("  First 3 lines of help:")
    lines = result.stdout.strip().split("\n")[:3]
    for line in lines:
        print(f"    {line}")
except Exception as e:
    print(f"  ERROR: {e}")

# Check 6: Test binary on a simple file
print("\n[6] BINARY TEST SCAN:")
test_file = r"C:\Windows\System32\notepad.exe"
try:
    result = subprocess.run([str(backend.binary_path), test_file], capture_output=True, text=True, timeout=10)
    print(f"  Exit code: {result.returncode}")
    print(f"  stdout length: {len(result.stdout)} bytes")
    print(f"  stderr length: {len(result.stderr)} bytes")

    if result.stdout:
        print("\n  First 500 chars of output:")
        print(f"  {result.stdout[:500]}")

    if result.stderr:
        print("\n  Errors:")
        print(f"  {result.stderr[:500]}")

except Exception as e:
    print(f"  ERROR: {e}")

# Check 7: Test backend scan method directly
print("\n[7] BACKEND SCAN TEST:")
try:
    v3_results = backend.scan(test_file)
    print(f"  Results returned: {len(v3_results)} modules")

    for module in v3_results:
        print(f"  Module has {len(module.results)} results")
        print(f"  Module has {len(module.errors)} errors")

        if module.errors:
            print(f"  Errors: {module.errors}")

        if module.results:
            print(f"  First result: {module.results[0]}")

except Exception as e:
    print(f"  ERROR: {type(e).__name__}: {e}")
    import traceback

    print("\n  Full traceback:")
    traceback.print_exc()

print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)
