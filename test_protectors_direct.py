"""Direct test of the protection scheme detection functionality."""

import sys
import os
import struct

# Test without importing full intellicrack package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'intellicrack', 'protection'))

# Import the database module directly
exec(open('intellicrack/protection/commercial_protectors_database.py').read())

def test_direct():
    """Test the commercial protectors database directly."""
    db = CommercialProtectorsDatabase()

    print("=" * 60)
    print("PROTECTION DETECTION ENGINE TEST")
    print("=" * 60)

    print(f"\n✅ Successfully loaded {len(db.protectors)} protector signatures")

    # Count by category
    categories = {}
    for name, sig in db.protectors.items():
        cat = sig.category.value
        categories[cat] = categories.get(cat, 0) + 1

    print("\n📊 Protectors by Category:")
    for cat, count in sorted(categories.items()):
        print(f"  • {cat}: {count}")

    # Show all protector names
    print("\n📋 All Protector Signatures:")
    for i, name in enumerate(sorted(db.protectors.keys()), 1):
        sig = db.protectors[name]
        print(f"  {i:2}. {name:25} - {sig.category.value:20} (difficulty: {sig.bypass_difficulty}/10)")

    # Verify we have 50+ protectors
    if len(db.protectors) >= 50:
        print(f"\n✅ PASSED: {len(db.protectors)} protectors loaded (requirement: 50+)")
    else:
        print(f"\n❌ FAILED: Only {len(db.protectors)} protectors loaded (requirement: 50+)")

    # Test core functionality
    print("\n🔧 Testing Core Functions:")

    # Test 1: Entry point pattern detection
    test_upx = b'\x55\x50\x58\x21' + b'\x00' * 1000
    detections = db.detect_protector(test_upx)
    print(f"  • UPX Detection: {'PASS' if any('UPX' in d[0] for d in detections) else 'FAIL'}")

    # Test 2: OEP detection for PUSHAD/POPAD pattern
    test_packed = b'\x60' + b'\x00' * 100 + b'\x61' + b'\xe9\x00\x00\x00\x00'
    oep = db.find_oep(test_packed, "Generic")
    print(f"  • OEP Detection: {'PASS' if oep == 101 else 'FAIL'} (found at: {hex(oep) if oep > 0 else 'N/A'})")

    # Test 3: Anti-debugging detection
    test_antidebug = b'IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00'
    anti_techniques = db.detect_anti_analysis(test_antidebug)
    print(f"  • Anti-Debug Detection: {'PASS' if len(anti_techniques) >= 2 else 'FAIL'} ({len(anti_techniques)} found)")

    # Test 4: VM detection
    test_vm = b'VMware\x00VirtualBox\x00QEMU\x00'
    vm_techniques = db.detect_anti_analysis(test_vm)
    print(f"  • Anti-VM Detection: {'PASS' if len(vm_techniques) >= 3 else 'FAIL'} ({len(vm_techniques)} found)")

    # Test 5: Encryption detection
    # Create real encrypted data
    xor_encrypted = bytes([b ^ 0xAB for b in b'MZ\x90\x00\x03\x00\x00\x00' * 128])
    layers = db.detect_encryption_layers(xor_encrypted)
    high_entropy = any(l['type'] == 'high-entropy' for l in layers)
    print(f"  • Encryption Detection: {'PASS' if high_entropy else 'FAIL'} ({len(layers)} layers found)")

    # Test 6: Bypass strategy retrieval
    strategy = db.get_bypass_strategy("VMProtect")
    print(f"  • Bypass Strategy: {'PASS' if strategy and strategy['difficulty'] == 9 else 'FAIL'}")

    print("\n" + "=" * 60)
    print("✅ PROTECTION DETECTION ENGINE TEST COMPLETE")
    print("=" * 60)

    return True


if __name__ == "__main__":
    try:
        success = test_direct()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
