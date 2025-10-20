import binwalk

def test_file(filepath, name):
    """Test binwalk on a file"""
    print(f"\n{'#'*70}")
    print(f"# Testing: {name}")
    print(f"# Path: {filepath}")
    print(f"{'#'*70}\n")

    try:
        results = binwalk.scan(filepath)

        for module in results:
            if len(module) == 0:
                print("❌ No signatures found in this file.\n")
            else:
                print(f"✓ Found {len(module)} embedded items:\n")

                for i, result in enumerate(module, 1):
                    print(f"  [{i}] Offset: 0x{result.offset:08X}")
                    print(f"      Type: {result.description}")
                    if result.size:
                        print(f"      Size: {result.size:,} bytes")
                    print()

    except Exception as e:
        print(f"❌ Error: {e}\n")


# Main execution
print("="*70)
print("BINWALK3 SYSTEM FILE TESTS")
print("="*70)

# Test 1: MSI Installer (Most interesting - contains CAB archives)
test_file(r'C:\Windows\Installer\12c491c.msi', 'Windows MSI Installer')

# Test 2: JAR File (ZIP archive with Java classes)
test_file(r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Browser\WCFirefoxExtn\chrome\WCFirefoxExtn.jar', 'Adobe JAR File')

# Test 3: Windows EXE (may contain embedded resources)
test_file(r'C:\Windows\System32\notepad.exe', 'Notepad.exe')

print("="*70)
print("TESTS COMPLETE!")
print("="*70)
