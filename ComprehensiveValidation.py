"""Comprehensive validation test suite for binwalk3 before publishing."""
import binwalk
import os
import tempfile
import zipfile
from pathlib import Path

# Test results tracking
tests_passed = 0
tests_failed = 0
test_details = []

def test_result(name, passed, details=""):
    """Record test result."""
    global tests_passed, tests_failed, test_details

    if passed:
        tests_passed += 1
        status = "✓ PASS"
    else:
        tests_failed += 1
        status = "✗ FAIL"

    print(f"{status}: {name}")
    if details:
        print(f"  {details}")

    test_details.append({
        'name': name,
        'passed': passed,
        'details': details
    })

print("="*80)
print("BINWALK3 COMPREHENSIVE VALIDATION TEST SUITE")
print("="*80)

# TEST 1: ZIP File Detection
print("\n[TEST 1] ZIP File Detection")
print("-" * 80)
test_zip = 'validation_test.zip'
try:
    with zipfile.ZipFile(test_zip, 'w') as zf:
        zf.writestr('test.txt', 'Test content')

    results = list(binwalk.scan(test_zip))

    if len(results) > 0 and len(results[0]) > 0:
        sig = results[0].results[0]
        if 'zip' in sig.description.lower() and sig.offset == 0:
            test_result("ZIP signature detection", True, f"Found: {sig.description}")
        else:
            test_result("ZIP signature detection", False, f"Wrong sig: {sig.description}")
    else:
        test_result("ZIP signature detection", False, "No signatures found")

    os.unlink(test_zip)
except Exception as e:
    test_result("ZIP signature detection", False, f"Exception: {e}")
    if os.path.exists(test_zip):
        os.unlink(test_zip)

# TEST 2: JAR File Detection (Real System File)
print("\n[TEST 2] JAR File Detection (Real System File)")
print("-" * 80)
jar_file = r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Browser\WCFirefoxExtn\chrome\WCFirefoxExtn.jar'
try:
    if os.path.exists(jar_file):
        results = list(binwalk.scan(jar_file))

        if len(results) > 0 and len(results[0]) > 0:
            sig = results[0].results[0]
            if 'zip' in sig.description.lower():
                test_result("JAR file detection", True, f"Found: {sig.description}")
            else:
                test_result("JAR file detection", False, f"Wrong sig: {sig.description}")
        else:
            test_result("JAR file detection", False, "No signatures found")
    else:
        test_result("JAR file detection", False, "JAR file not found on system")
except Exception as e:
    test_result("JAR file detection", False, f"Exception: {e}")

# TEST 3: MSI File Detection (Real System File)
print("\n[TEST 3] MSI File Detection (Real System File)")
print("-" * 80)
msi_file = r'C:\Windows\Installer\12c491c.msi'
try:
    if os.path.exists(msi_file):
        results = list(binwalk.scan(msi_file))

        if len(results) > 0 and len(results[0]) > 0:
            test_result("MSI file detection", True, f"Found {len(results[0])} signatures")
        else:
            test_result("MSI file detection", False, "No signatures found")
    else:
        test_result("MSI file detection", False, "MSI file not found on system")
except Exception as e:
    test_result("MSI file detection", False, f"Exception: {e}")

# TEST 4: Embedded ZIP at Offset
print("\n[TEST 4] Embedded ZIP at Offset")
print("-" * 80)
firmware_file = 'validation_firmware.bin'
try:
    with zipfile.ZipFile('temp.zip', 'w') as zf:
        zf.writestr('data.bin', b'\x00' * 100)

    with open(firmware_file, 'wb') as f:
        f.write(b'HEADER' * 50)  # 300 bytes header
        with open('temp.zip', 'rb') as zf:
            f.write(zf.read())
        f.write(b'\xFF' * 100)

    results = list(binwalk.scan(firmware_file))

    if len(results) > 0 and len(results[0]) > 0:
        sig = results[0].results[0]
        if sig.offset == 300 and 'zip' in sig.description.lower():
            test_result("Embedded ZIP detection", True, f"Found at offset {sig.offset}")
        else:
            test_result("Embedded ZIP detection", False, f"Wrong offset: {sig.offset}")
    else:
        test_result("Embedded ZIP detection", False, "No signatures found")

    os.unlink(firmware_file)
    os.unlink('temp.zip')
except Exception as e:
    test_result("Embedded ZIP detection", False, f"Exception: {e}")
    for f in [firmware_file, 'temp.zip']:
        if os.path.exists(f):
            os.unlink(f)

# TEST 5: Extraction Functionality
print("\n[TEST 5] Extraction Functionality")
print("-" * 80)
extract_test = 'extract_test.zip'
try:
    with zipfile.ZipFile(extract_test, 'w') as zf:
        zf.writestr('extracted.txt', 'This should be extracted')

    with tempfile.TemporaryDirectory() as tmpdir:
        results = list(binwalk.scan(extract_test, extract=True, directory=tmpdir, quiet=True))

        # Check if extraction created output directory
        extract_dir = Path(tmpdir)
        extracted_files = list(extract_dir.rglob('*'))

        if len(extracted_files) > 0:
            test_result("Extraction functionality", True, f"Extracted {len(extracted_files)} items")
        else:
            test_result("Extraction functionality", False, "No files extracted")

    os.unlink(extract_test)
except Exception as e:
    test_result("Extraction functionality", False, f"Exception: {e}")
    if os.path.exists(extract_test):
        os.unlink(extract_test)

# TEST 6: Entropy Calculation
print("\n[TEST 6] Entropy Calculation")
print("-" * 80)
entropy_test = 'entropy_test.bin'
try:
    # Create file with random data (high entropy) and zeros (low entropy)
    with open(entropy_test, 'wb') as f:
        f.write(os.urandom(1024))  # High entropy
        f.write(b'\x00' * 1024)    # Low entropy

    results = list(binwalk.scan(entropy_test, entropy=True))

    if len(results) > 0:
        test_result("Entropy calculation", True, f"Entropy analysis completed")
    else:
        test_result("Entropy calculation", False, "No entropy results")

    os.unlink(entropy_test)
except Exception as e:
    test_result("Entropy calculation", False, f"Exception: {e}")
    if os.path.exists(entropy_test):
        os.unlink(entropy_test)

# TEST 7: Non-existent File Handling
print("\n[TEST 7] Error Handling - Non-existent File")
print("-" * 80)
try:
    results = list(binwalk.scan('this_file_does_not_exist.bin'))

    if len(results) > 0:
        module = results[0]
        if len(module.errors) > 0 and 'not found' in module.errors[0].lower():
            test_result("Non-existent file handling", True, "Proper error reported")
        else:
            test_result("Non-existent file handling", False, "No error for missing file")
    else:
        test_result("Non-existent file handling", False, "No module result")
except Exception as e:
    test_result("Non-existent file handling", False, f"Exception: {e}")

# TEST 8: Multiple Files Scan
print("\n[TEST 8] Multiple Files Scanning")
print("-" * 80)
try:
    file1 = 'multi_test1.zip'
    file2 = 'multi_test2.zip'

    with zipfile.ZipFile(file1, 'w') as zf:
        zf.writestr('file1.txt', 'File 1')
    with zipfile.ZipFile(file2, 'w') as zf:
        zf.writestr('file2.txt', 'File 2')

    results = list(binwalk.scan(file1, file2))

    if len(results) == 2:
        if len(results[0]) > 0 and len(results[1]) > 0:
            test_result("Multiple files scanning", True, "Both files scanned successfully")
        else:
            test_result("Multiple files scanning", False, "Some files returned no results")
    else:
        test_result("Multiple files scanning", False, f"Expected 2 results, got {len(results)}")

    os.unlink(file1)
    os.unlink(file2)
except Exception as e:
    test_result("Multiple files scanning", False, f"Exception: {e}")
    for f in ['multi_test1.zip', 'multi_test2.zip']:
        if os.path.exists(f):
            os.unlink(f)

# TEST 9: Empty File Handling
print("\n[TEST 9] Empty File Handling")
print("-" * 80)
empty_file = 'empty_test.bin'
try:
    Path(empty_file).touch()

    results = list(binwalk.scan(empty_file))

    if len(results) > 0:
        test_result("Empty file handling", True, "Handled without crash")
    else:
        test_result("Empty file handling", False, "No module result")

    os.unlink(empty_file)
except Exception as e:
    test_result("Empty file handling", False, f"Exception: {e}")
    if os.path.exists(empty_file):
        os.unlink(empty_file)

# TEST 10: Signature=True Parameter
print("\n[TEST 10] Signature Parameter")
print("-" * 80)
try:
    with zipfile.ZipFile('sig_test.zip', 'w') as zf:
        zf.writestr('test.txt', 'Test')

    results = list(binwalk.scan('sig_test.zip', signature=True))

    if len(results) > 0 and len(results[0]) > 0:
        test_result("Signature parameter", True, "Signature scanning works")
    else:
        test_result("Signature parameter", False, "No signatures with signature=True")

    os.unlink('sig_test.zip')
except Exception as e:
    test_result("Signature parameter", False, f"Exception: {e}")
    if os.path.exists('sig_test.zip'):
        os.unlink('sig_test.zip')

# FINAL RESULTS
print("\n" + "="*80)
print("VALIDATION RESULTS")
print("="*80)
print(f"Tests Passed: {tests_passed}")
print(f"Tests Failed: {tests_failed}")
print(f"Success Rate: {tests_passed}/{tests_passed + tests_failed} ({100*tests_passed/(tests_passed+tests_failed):.1f}%)")

if tests_failed == 0:
    print("\n✓ ALL TESTS PASSED - Package is ready for publishing")
else:
    print(f"\n✗ {tests_failed} TESTS FAILED - DO NOT PUBLISH")
    print("\nFailed tests:")
    for test in test_details:
        if not test['passed']:
            print(f"  - {test['name']}: {test['details']}")

print("="*80)
