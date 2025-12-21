"""Test binwalk3 on real system binaries with actual embedded content."""
import binwalk
import os
from pathlib import Path

tests_passed = 0
tests_failed = 0

def test_binary(filepath, name, expected_signatures_min=1):
    """Test a real binary file."""
    global tests_passed, tests_failed

    print(f"\n{'='*80}")
    print(f"Testing: {name}")
    print(f"File: {filepath}")
    print('='*80)

    if not os.path.exists(filepath):
        print("FAIL SKIP: File not found")
        return

    filesize = os.path.getsize(filepath)
    print(f"Size: {filesize:,} bytes")

    try:
        results = list(binwalk.scan(filepath))

        if not results:
            print("FAIL FAIL: No module results returned")
            tests_failed += 1
            return

        module = results[0]

        if module.errors:
            print("FAIL FAIL: Errors encountered:")
            for error in module.errors:
                print(f"  - {error}")
            tests_failed += 1
            return

        num_sigs = len(module.results)
        print(f"\nSignatures found: {num_sigs}")

        if num_sigs >= expected_signatures_min:
            print(f"OK PASS: Found {num_sigs} signatures (expected >= {expected_signatures_min})")
            tests_passed += 1

            # Show first few signatures
            for i, sig in enumerate(module.results[:5]):
                print(f"  [{i+1}] Offset: 0x{sig.offset:08X} ({sig.offset:,} bytes)")
                print(f"      Type: {sig.description}")
                if sig.size:
                    print(f"      Size: {sig.size:,} bytes")

            if num_sigs > 5:
                print(f"  ... and {num_sigs - 5} more signatures")
        else:
            print(f"FAIL FAIL: Found {num_sigs} signatures, expected at least {expected_signatures_min}")
            tests_failed += 1

    except Exception as e:
        print(f"FAIL FAIL: Exception - {e}")
        import traceback
        traceback.print_exc()
        tests_failed += 1

print("="*80)
print("REAL BINARY VALIDATION TESTS")
print("="*80)

# Test 1: Windows Installer MSI (contains CAB archives)
test_binary(
    r'C:\Windows\Installer\12c491c.msi',
    'Windows MSI Installer (MSI format with embedded CAB)',
    expected_signatures_min=1
)

# Test 2: JAR file (ZIP archive)
test_binary(
    r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Browser\WCFirefoxExtn\chrome\WCFirefoxExtn.jar',
    'Adobe JAR File (ZIP archive with Java classes)',
    expected_signatures_min=1
)

# Test 3: Windows EXE with resources
test_binary(
    r'C:\Windows\System32\notepad.exe',
    'Notepad.exe (PE executable with embedded resources)',
    expected_signatures_min=1
)

# Test 4: DLL with embedded resources
test_binary(
    r'C:\Windows\System32\kernel32.dll',
    'kernel32.dll (System DLL with resources)',
    expected_signatures_min=1
)

# Test 5: Windows System File
test_binary(
    r'C:\Windows\System32\shell32.dll',
    'shell32.dll (Shell DLL with icons/resources)',
    expected_signatures_min=1
)

# Test 6: Larger executable
test_binary(
    r'C:\Windows\System32\mmc.exe',
    'Microsoft Management Console (Large EXE)',
    expected_signatures_min=1
)

# Test 7: Check Windows Update packages if they exist
winsxs_path = Path(r'C:\Windows\WinSxS')
if winsxs_path.exists():
    # Find a .manifest or .cat file
    manifest_files = list(winsxs_path.glob('*.manifest'))[:1]
    for manifest in manifest_files:
        test_binary(
            str(manifest),
            f'WinSxS Manifest ({manifest.name})',
            expected_signatures_min=0  # May or may not have signatures
        )

# Final Results
print("\n" + "="*80)
print("REAL BINARY VALIDATION RESULTS")
print("="*80)
print(f"Tests Passed: {tests_passed}")
print(f"Tests Failed: {tests_failed}")

if tests_failed == 0 and tests_passed > 0:
    print(f"\nOK ALL TESTS PASSED ({tests_passed}/{tests_passed})")
    print("Package validated on real system binaries")
elif tests_passed > 0:
    success_rate = 100 * tests_passed / (tests_passed + tests_failed)
    print(f"\n⚠ PARTIAL SUCCESS: {success_rate:.1f}% ({tests_passed}/{tests_passed + tests_failed})")
else:
    print("\nFAIL ALL TESTS FAILED")

print("="*80)
