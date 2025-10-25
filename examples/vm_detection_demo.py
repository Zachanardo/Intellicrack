"""VM Detection Demo - Showcasing Enhanced Detection Capabilities.

This example demonstrates the sophisticated VM detection features
in Intellicrack for security research and licensing protection analysis.
"""

from intellicrack.core.anti_analysis.vm_detector import VMDetector


def main():
    print("=" * 80)
    print("Intellicrack VM Detector - Enhanced Capabilities Demo")
    print("=" * 80)

    detector = VMDetector()

    print("\n[1] Basic VM Detection")
    print("-" * 80)
    results = detector.detect_vm(aggressive=False)

    print(f"VM Detected: {results['is_vm']}")
    print(f"VM Type: {results['vm_type']}")
    print(f"Confidence: {results['confidence']:.2%}")
    print(f"Evasion Score: {results['evasion_score']}/10")

    print(f"\nDetection Methods Triggered: {sum(1 for r in results['detections'].values() if r['detected'])}")

    for method, data in results['detections'].items():
        if data['detected']:
            print(f"  - {method}: {data['confidence']:.2%}")

    print("\n[2] Hardware Fingerprinting")
    print("-" * 80)
    fingerprint = detector.get_hardware_fingerprint()

    print(f"CPU Vendor: {fingerprint.cpu_vendor}")
    print(f"CPU Model: {fingerprint.cpu_model}")
    print(f"CPU Cores: {fingerprint.cpu_cores}")
    print(f"Total RAM: {fingerprint.total_ram_mb} MB")
    print(f"Disk Count: {fingerprint.disk_count}")
    print(f"System: {fingerprint.system_manufacturer} {fingerprint.system_model}")
    print(f"BIOS: {fingerprint.bios_vendor}")
    print(f"Fingerprint Hash: {fingerprint.fingerprint_hash[:16]}...")

    if fingerprint.mac_addresses:
        print(f"MAC Addresses: {len(fingerprint.mac_addresses)}")
        for mac in fingerprint.mac_addresses[:3]:
            print(f"  - {mac}")

    if fingerprint.disk_serials:
        print(f"Disk Serials: {len(fingerprint.disk_serials)}")
        for serial in fingerprint.disk_serials[:3]:
            print(f"  - {serial}")

    print("\n[3] Timing Analysis")
    print("-" * 80)
    timing_measurements = detector.analyze_timing_patterns()

    for operation, measurement in timing_measurements.items():
        print(f"\n{operation}:")
        print(f"  Mean: {measurement.mean:.2f}ns")
        print(f"  Std Dev: {measurement.std_dev:.2f}ns")
        print(f"  Range: {measurement.min_val}ns - {measurement.max_val}ns")
        if measurement.anomaly_detected:
            print(f"  ANOMALY DETECTED (confidence: {measurement.confidence:.2%})")

    print("\n[4] Individual Detection Methods")
    print("-" * 80)

    print("\nCPUID Feature Flags:")
    detected, confidence, details = detector._check_cpuid_feature_flags()
    print(f"  Detected: {detected} (confidence: {confidence:.2%})")
    if details.get('ecx_features'):
        print(f"  Features: {', '.join(details['ecx_features'][:5])}")

    print("\nExtended CPUID Leaves:")
    detected, confidence, details = detector._check_cpuid_extended_leaves()
    print(f"  Detected: {detected} (confidence: {confidence:.2%})")
    if details.get('hypervisor_info', {}).get('vendor_string'):
        print(f"  Vendor: {details['hypervisor_info']['vendor_string']}")

    print("\nCPU Brand String:")
    detected, confidence, details = detector._check_cpuid_brand_string()
    print(f"  Detected: {detected} (confidence: {confidence:.2%})")
    if details.get('brand_string'):
        print(f"  Brand: {details['brand_string']}")

    print("\n[5] Aggressive Detection (Timing-Based)")
    print("-" * 80)
    results_aggressive = detector.detect_vm(aggressive=True)

    print(f"VM Detected: {results_aggressive['is_vm']}")
    print(f"Confidence: {results_aggressive['confidence']:.2%}")
    print(f"Evasion Score: {results_aggressive['evasion_score']}/10")

    aggressive_methods = [
        'rdtsc_vmexit_detection',
        'paravirt_instructions',
        'memory_artifacts',
        'tsc_frequency_analysis',
        'cache_timing'
    ]

    print("\nAdvanced Timing Methods:")
    for method in aggressive_methods:
        if method in results_aggressive['detections']:
            data = results_aggressive['detections'][method]
            if data['detected']:
                print(f"  {method}: DETECTED ({data['confidence']:.2%})")
            else:
                print(f"  {method}: Not detected")

    print("\n" + "=" * 80)
    print("Demo Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
