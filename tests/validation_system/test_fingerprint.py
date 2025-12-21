#!/usr/bin/env python3
"""Test fingerprint randomizer."""


import sys
sys.path.insert(0, r'D:\Intellicrack')

from tests.validation_system.fingerprint_randomizer import SystemFingerprinter, FingerprintRandomizer

print("Testing Fingerprint Randomizer...")
print("-" * 50)

# Test fingerprinter
fp = SystemFingerprinter()
print("SystemFingerprinter initialized")

fingerprint = fp.collect_fingerprint()
print("Fingerprint collected")
print(f"  Hash: {fingerprint['hash'][:16]}...")
print(f"  Categories: {list(fingerprint.keys())}")

# Show some details
hw = fingerprint['hardware']
if 'cpu' in hw:
    print(f"  CPU: {hw['cpu']['name']}")

sw = fingerprint['software']
if 'os' in sw:
    print(f"  OS: {sw['os']['name'].split('|')[0] if '|' in sw['os']['name'] else sw['os']['name'][:50]}")

# Test randomizer initialization
print("\nTesting FingerprintRandomizer...")
randomizer = FingerprintRandomizer()
print("FingerprintRandomizer initialized")

print("\nOK Fingerprint Randomizer Test Complete!")
