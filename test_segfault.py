"""Granular diagnostic to identify exact segfault location."""
import sys

print("=== SEGFAULT DIAGNOSTIC ===", flush=True)
print("Step 1: Basic imports", flush=True)
import logging
import os
import warnings
print("  ✓ Step 1 complete", flush=True)

print("Step 2: Import torch_gil_safety MODULE (not function)", flush=True)
try:
    import intellicrack.utils.torch_gil_safety as tgs_module
    print("  ✓ Step 2 complete - module imported", flush=True)
except Exception as e:
    print(f"  ✗ Step 2 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 3: Import initialize_gil_safety FUNCTION", flush=True)
try:
    from intellicrack.utils.torch_gil_safety import initialize_gil_safety
    print("  ✓ Step 3 complete - function imported", flush=True)
except Exception as e:
    print(f"  ✗ Step 3 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 4: CALL initialize_gil_safety()", flush=True)
try:
    initialize_gil_safety()
    print("  ✓ Step 4 complete - function called", flush=True)
except Exception as e:
    print(f"  ✗ Step 4 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 5: Import security_enforcement MODULE", flush=True)
try:
    from intellicrack.core import security_enforcement
    print("  ✓ Step 5 complete", flush=True)
except Exception as e:
    print(f"  ✗ Step 5 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 6: Import security_mitigations", flush=True)
try:
    from intellicrack.utils.security_mitigations import apply_all_mitigations
    print("  ✓ Step 6 complete", flush=True)
except Exception as e:
    print(f"  ✗ Step 6 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 7: CALL apply_all_mitigations()", flush=True)
try:
    apply_all_mitigations()
    print("  ✓ Step 7 complete", flush=True)
except Exception as e:
    print(f"  ✗ Step 7 FAILED: {e}", flush=True)
    sys.exit(1)

print("Step 8: Import intellicrack.main", flush=True)
try:
    import intellicrack.main
    print("  ✓ Step 8 complete", flush=True)
except Exception as e:
    print(f"  ✗ Step 8 FAILED: {e}", flush=True)
    sys.exit(1)

print("\n=== ALL STEPS PASSED ===", flush=True)
