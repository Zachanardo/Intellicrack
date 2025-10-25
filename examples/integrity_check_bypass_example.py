"""Example demonstrating integrity check bypass capabilities.

This example shows how to:
1. Detect integrity checks in a binary
2. Recalculate checksums for patched binaries
3. Generate Frida bypass scripts
4. Patch binaries to remove integrity checks
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.protection_bypass.integrity_check_defeat import (
    ChecksumRecalculator,
    IntegrityCheckDefeatSystem,
)

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')


def example_checksum_calculation():
    """Demonstrate checksum calculation capabilities."""
    print("\n" + "="*60)
    print("EXAMPLE 1: Checksum Calculation")
    print("="*60)

    calc = ChecksumRecalculator()

    test_data = b"This is a test binary with integrity protection"

    checksums = calc.calculate_all_hashes(test_data)

    print("\nCalculated checksums for test data:")
    print(f"  CRC32:   {checksums['crc32']}")
    print(f"  MD5:     {checksums['md5']}")
    print(f"  SHA1:    {checksums['sha1']}")
    print(f"  SHA256:  {checksums['sha256']}")


def example_binary_analysis(binary_path: str):
    """Demonstrate binary integrity check detection."""
    print("\n" + "="*60)
    print("EXAMPLE 2: Binary Integrity Check Detection")
    print("="*60)

    if not Path(binary_path).exists():
        print(f"\nBinary not found: {binary_path}")
        print("Skipping binary analysis example")
        return

    system = IntegrityCheckDefeatSystem()

    print(f"\nAnalyzing binary: {binary_path}")

    result = system.defeat_integrity_checks(binary_path)

    print("\nDetection Results:")
    print(f"  Checks detected: {result['checks_detected']}")
    print(f"  Success: {result['success']}")

    if result['details']:
        print("\nDetected integrity checks:")
        for i, detail in enumerate(result['details'], 1):
            print(f"\n  Check #{i}:")
            print(f"    Type: {detail['type']}")
            print(f"    Address: {detail['address']}")
            print(f"    Function: {detail['function']}")
            print(f"    Bypass method: {detail['bypass_method']}")
            print(f"    Confidence: {detail['confidence']:.1%}")
            if detail.get('section'):
                print(f"    Section: {detail['section']}")


def example_frida_script_generation(binary_path: str):
    """Demonstrate Frida bypass script generation."""
    print("\n" + "="*60)
    print("EXAMPLE 3: Frida Bypass Script Generation")
    print("="*60)

    if not Path(binary_path).exists():
        print(f"\nBinary not found: {binary_path}")
        print("Skipping script generation example")
        return

    system = IntegrityCheckDefeatSystem()

    print(f"\nGenerating bypass script for: {binary_path}")

    script = system.generate_bypass_script(binary_path)

    print("\nGenerated Frida script:")
    print("-" * 60)
    print(script[:500] + "..." if len(script) > 500 else script)
    print("-" * 60)


def example_binary_patching(binary_path: str):
    """Demonstrate binary patching with checksum recalculation."""
    print("\n" + "="*60)
    print("EXAMPLE 4: Binary Patching with Checksum Recalculation")
    print("="*60)

    if not Path(binary_path).exists():
        print(f"\nBinary not found: {binary_path}")
        print("Skipping binary patching example")
        return

    system = IntegrityCheckDefeatSystem()

    print(f"\nPatching binary: {binary_path}")
    print("Note: This will create a .patched version of the binary")

    result = system.defeat_integrity_checks(
        binary_path,
        process_name=None,
        patch_binary=True
    )

    print("\nPatching Results:")
    print(f"  Checks detected: {result['checks_detected']}")
    print(f"  Binary patched: {result['binary_patched']}")
    print(f"  Success: {result['success']}")

    if result.get('checksums'):
        cs = result['checksums']
        print("\nChecksum Recalculation:")
        print(f"  Original CRC32: {cs['original_crc32']}")
        print(f"  Patched CRC32:  {cs['patched_crc32']}")
        print(f"  Original MD5:   {cs['original_md5']}")
        print(f"  Patched MD5:    {cs['patched_md5']}")
        print(f"  PE Checksum:    {cs['pe_checksum']}")

        if cs.get('sections'):
            print("\nSection-level hashes (patched binary):")
            for section_name, hashes in list(cs['sections'].items())[:3]:
                print(f"\n  {section_name}:")
                print(f"    MD5:    {hashes['md5']}")
                print(f"    SHA256: {hashes['sha256']}")


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("INTEGRITY CHECK BYPASS SYSTEM - EXAMPLES")
    print("="*60)

    example_checksum_calculation()

    test_binary = r"C:\Windows\System32\notepad.exe"

    example_binary_analysis(test_binary)
    example_frida_script_generation(test_binary)

    print("\n" + "="*60)
    print("EXAMPLES COMPLETED")
    print("="*60)
    print("\nNote: Binary patching example skipped to avoid modifying system files.")
    print("To test patching, provide your own test binary.\n")


if __name__ == "__main__":
    main()
