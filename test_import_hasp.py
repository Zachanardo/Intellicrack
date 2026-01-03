#!/usr/bin/env python3
"""Test import of HASP parser."""

import sys

try:
    from intellicrack.core.network.protocols.hasp_parser import (
        HASPCrypto,
        HASPSentinelParser,
        HASPUSBEmulator,
        HASPServerEmulator,
        HASPPacketAnalyzer,
        HASPVariant,
        HASPEncryptionType,
    )

    print("✓ Import successful")
    print(f"✓ HASPCrypto: {HASPCrypto}")
    print(f"✓ HASPSentinelParser: {HASPSentinelParser}")
    print(f"✓ HASPUSBEmulator: {HASPUSBEmulator}")
    print(f"✓ HASPServerEmulator: {HASPServerEmulator}")
    print(f"✓ HASPPacketAnalyzer: {HASPPacketAnalyzer}")
    print(f"✓ HASPVariant: {HASPVariant}")
    print(f"✓ HASPEncryptionType: {HASPEncryptionType}")

    print("\n✓ Testing basic instantiation...")
    parser = HASPSentinelParser(variant=HASPVariant.HASP_HL_MAX)
    print(f"✓ Parser variant: {parser.variant}")
    print(f"✓ Parser features: {len(parser.features)}")

    crypto = HASPCrypto()
    test_data = b"Hello HASP World!"
    encrypted = crypto.aes_encrypt(test_data, 0, "CBC", 256)
    print(f"✓ Encrypted {len(test_data)} bytes to {len(encrypted)} bytes")

    decrypted = crypto.aes_decrypt(encrypted, 0, "CBC", 256)
    print(f"✓ Decrypted back to {len(decrypted)} bytes")

    if decrypted == test_data:
        print("✓ Encryption/decryption roundtrip successful!")
    else:
        print("✗ Encryption/decryption roundtrip failed!")
        sys.exit(1)

    print("\n✓ ALL TESTS PASSED")
    sys.exit(0)

except Exception as e:
    print(f"✗ Import or test failed: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
