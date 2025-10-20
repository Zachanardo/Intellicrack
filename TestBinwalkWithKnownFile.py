import binwalk
import zipfile
import os

print("="*70)
print("CREATING TEST FILE WITH KNOWN SIGNATURES")
print("="*70)

# Create a test ZIP file (guaranteed to be detected)
print("\n[1] Creating test ZIP file...")
test_zip = 'test_file.zip'
with zipfile.ZipFile(test_zip, 'w') as zf:
    zf.writestr('test.txt', 'This is a test file inside a ZIP archive')
    zf.writestr('data.bin', b'\x00' * 1000)

print(f"  ✓ Created: {test_zip} ({os.path.getsize(test_zip)} bytes)")

# Create a test file with ZIP embedded at offset
print("\n[2] Creating firmware-like file with embedded ZIP...")
test_firmware = 'test_firmware.bin'
with open(test_firmware, 'wb') as f:
    # Write header
    f.write(b'FIRMWARE_HEADER_1.0\x00' * 10)  # 200 bytes header

    # Embed the ZIP file
    with open(test_zip, 'rb') as zip_f:
        f.write(zip_f.read())

    # Add footer
    f.write(b'\xFF' * 100)

print(f"  ✓ Created: {test_firmware} ({os.path.getsize(test_firmware)} bytes)")

# Test 1: Scan the pure ZIP file
print("\n" + "="*70)
print("TEST 1: Scanning pure ZIP file")
print("="*70)
for module in binwalk.scan(test_zip):
    if len(module) == 0:
        print("❌ No signatures found")
    else:
        print(f"✓ Found {len(module)} signatures:")
        for result in module:
            print(f"  0x{result.offset:08X}: {result.description}")

# Test 2: Scan the firmware-like file
print("\n" + "="*70)
print("TEST 2: Scanning firmware file with embedded ZIP")
print("="*70)
for module in binwalk.scan(test_firmware):
    if len(module) == 0:
        print("❌ No signatures found")
    else:
        print(f"✓ Found {len(module)} signatures:")
        for result in module:
            print(f"  0x{result.offset:08X} ({result.offset} bytes): {result.description}")

# Test 3: Try with signature scanning explicitly enabled
print("\n" + "="*70)
print("TEST 3: Scanning with signature=True")
print("="*70)
for module in binwalk.scan(test_firmware, signature=True):
    if len(module) == 0:
        print("❌ No signatures found")
    else:
        print(f"✓ Found {len(module)} signatures:")
        for result in module:
            print(f"  0x{result.offset:08X}: {result.description}")

# Test 4: Try scanning with verbose
print("\n" + "="*70)
print("TEST 4: Scanning the JAR file (should be ZIP)")
print("="*70)
jar_file = r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Browser\WCFirefoxExtn\chrome\WCFirefoxExtn.jar'
for module in binwalk.scan(jar_file):
    if len(module) == 0:
        print("❌ No signatures found in JAR")
    else:
        print(f"✓ Found {len(module)} signatures in JAR:")
        for result in module:
            print(f"  0x{result.offset:08X}: {result.description}")

# Test 5: Check first few bytes of JAR to verify it's a ZIP
print("\n" + "="*70)
print("TEST 5: Checking JAR file header")
print("="*70)
if os.path.exists(jar_file):
    with open(jar_file, 'rb') as f:
        header = f.read(10)
        print(f"First 10 bytes (hex): {header.hex()}")
        print(f"First 10 bytes (ascii): {header}")
        print(f"Is ZIP signature? {header[:2] == b'PK'}")

print("\n" + "="*70)
print("TESTS COMPLETE")
print("="*70)
print("\nCleanup:")
print(f"  rm {test_zip}")
print(f"  rm {test_firmware}")
