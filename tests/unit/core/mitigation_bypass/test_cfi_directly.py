"""
Direct test execution for CFI bypass module.
"""

import sys
import os
import traceback

# Add project to path
sys.path.insert(0, r"D:\Intellicrack")

print("Testing CFI Bypass Module")
print("=" * 80)

try:
    from intellicrack.core.mitigation_bypass.cfi_bypass import CFIBypass
    MODULE_AVAILABLE = True
except ImportError:
    CFIBypass = None
    MODULE_AVAILABLE = False

try:
    import pytest
    pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")
except ImportError:
    pass

if MODULE_AVAILABLE:
    print("OK Successfully imported CFIBypass from mitigation_bypass")
else:
    print("ERROR Could not import CFIBypass")
    sys.exit(1)

try:

    # Create instance
    cfi = CFIBypass()
    print("OK Successfully created CFIBypass instance")

    # Test basic functionality
    import tempfile

    # Create a test binary
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b'MZ' + b'\x00' * 1024)
        test_file = f.name

    print(f"\nTesting with file: {test_file}")

    # Test analyze_cfi_protection
    print("\n1. Testing analyze_cfi_protection...")
    result = cfi.analyze_cfi_protection(test_file)
    print(f"   Result type: {type(result)}")
    print(f"   Result: {result}")

    # Test find_rop_gadgets
    print("\n2. Testing find_rop_gadgets...")
    gadgets = cfi.find_rop_gadgets(test_file)
    print(f"   Found {len(gadgets) if gadgets else 0} ROP gadgets")

    # Test find_jop_gadgets
    print("\n3. Testing find_jop_gadgets...")
    jop_gadgets = cfi.find_jop_gadgets(test_file)
    print(f"   Found {len(jop_gadgets) if jop_gadgets else 0} JOP gadgets")

    # Test get_available_bypass_methods
    print("\n4. Testing get_available_bypass_methods...")
    methods = cfi.get_available_bypass_methods()
    print(f"   Available methods: {len(methods) if methods else 0}")

    # Test generate_bypass_payload
    print("\n5. Testing generate_bypass_payload...")
    payload = cfi.generate_bypass_payload(
        test_file,
        technique='rop_chain',
        target_address=0x140001000
    )
    print(f"   Payload type: {type(payload)}")
    print(f"   Payload length: {len(payload) if payload else 0}")

    print("\n" + "=" * 80)
    print("BASIC FUNCTIONALITY TEST COMPLETE")

    # Now run the actual test suite
    print("\n" + "=" * 80)
    print("RUNNING FULL TEST SUITE")
    print("=" * 80)

    import pytest

    # Run pytest programmatically
    exit_code = pytest.main([
        'tests/unit/core/mitigation_bypass/test_cfi_bypass.py',
        '-v',
        '--tb=short',
        '--cov=intellicrack.core.exploitation.cfi_bypass',
        '--cov=intellicrack.core.mitigation_bypass.cfi_bypass',
        '--cov-report=term-missing',
        '--cov-report=html'
    ])

    print(f"\nTest suite exit code: {exit_code}")

except ImportError as e:
    print(f"FAIL Import error: {e}")
    traceback.print_exc()
except Exception as e:
    print(f"FAIL Error: {e}")
    traceback.print_exc()

print("\nTest execution complete.")
