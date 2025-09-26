"""Test the protection scheme detection functionality."""

import sys
import os

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import only the necessary module directly
from intellicrack.protection.commercial_protectors_database import (
    CommercialProtectorsDatabase,
    ProtectorCategory
)


def test_protection_database():
    """Test the commercial protectors database."""
    db = CommercialProtectorsDatabase()

    print(f"✓ Loaded {len(db.protectors)} protector signatures")

    # Count by category
    categories = {}
    for name, sig in db.protectors.items():
        cat = sig.category.value
        categories[cat] = categories.get(cat, 0) + 1

    print("\n📊 Protectors by Category:")
    for cat, count in sorted(categories.items()):
        print(f"  • {cat}: {count}")

    # Test detection on sample bytes
    print("\n🔍 Testing Detection Methods:")

    # Test with UPX-like pattern
    test_data = b'\x55\x50\x58\x21' + b'\x00' * 1000
    detections = db.detect_protector(test_data)
    print(f"  • Pattern matching: {'✓' if detections else '✗'}")

    # Test OEP detection
    oep = db.find_oep(b'\x60' + b'\x00' * 100 + b'\x61\xe9\x00\x00\x00\x00', "Generic")
    print(f"  • OEP detection: {'✓' if oep > 0 else '✗'} (offset: {hex(oep) if oep > 0 else 'N/A'})")

    # Test anti-analysis detection
    test_data = b'IsDebuggerPresent' + b'VMware' + b'GetTickCount'
    anti_techniques = db.detect_anti_analysis(test_data)
    print(f"  • Anti-analysis detection: {'✓' if anti_techniques else '✗'} ({len(anti_techniques)} techniques found)")

    # Test encryption layer detection
    # Real XOR encrypted data pattern (common in packers)
    xor_key = 0xAB
    plaintext = b'This program cannot be run in DOS mode' * 10
    encrypted_data = bytes(b ^ xor_key for b in plaintext) + b'\x1f\x8b\x08\x00' + b'\x00' * 100  # Add GZIP header
    layers = db.detect_encryption_layers(encrypted_data)
    print(f"  • Encryption detection: {'✓' if layers else '✗'} ({len(layers)} layers found)")

    # Show some protector names
    print("\n📋 Sample Protectors (first 10):")
    for i, name in enumerate(list(db.protectors.keys())[:10]):
        sig = db.protectors[name]
        print(f"  {i+1}. {name} - {sig.category.value} (difficulty: {sig.bypass_difficulty}/10)")

    print(f"\n✅ Protection detection engine loaded successfully!")
    print(f"   Total protectors: {len(db.protectors)}")
    print(f"   Categories: {len(categories)}")

    return True


if __name__ == "__main__":
    try:
        success = test_protection_database()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
