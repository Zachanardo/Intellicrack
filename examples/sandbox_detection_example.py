"""Sandbox Detection and Evasion Example.

Demonstrates the enhanced sandbox detection capabilities of Intellicrack
for security research on software licensing protection systems.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

import json
import logging

from intellicrack.core.anti_analysis.sandbox_detector import SandboxDetector


def basic_detection_example():
    """Basic sandbox detection example."""
    print("=" * 70)
    print("BASIC SANDBOX DETECTION")
    print("=" * 70)

    detector = SandboxDetector()
    results = detector.detect_sandbox()

    print(f"\nSandbox Detected: {results['is_sandbox']}")
    print(f"Confidence: {results['confidence']:.2%}")
    print(f"Sandbox Type: {results['sandbox_type']}")
    print(f"Evasion Difficulty: {results['evasion_difficulty']}/10")

    print("\nDetection Methods:")
    for method, data in results['detections'].items():
        if data['detected']:
            conf = data['confidence']
            conf_str = f"{conf:.2%}" if isinstance(conf, (int, float)) else str(conf)
            print(f"  ✓ {method}: {conf_str} confidence")
            if 'details' in data:
                print(f"    Details: {json.dumps(data['details'], indent=6)[:200]}...")

    return results


def aggressive_detection_example():
    """Aggressive detection with all methods enabled."""
    print("\n" + "=" * 70)
    print("AGGRESSIVE SANDBOX DETECTION")
    print("=" * 70)

    detector = SandboxDetector()
    results = detector.detect_sandbox(aggressive=True)

    print(f"\nSandbox Detected: {results['is_sandbox']}")
    print(f"Confidence: {results['confidence']:.2%}")

    detected_methods = [m for m, d in results['detections'].items() if d['detected']]
    print(f"\nTriggered Detection Methods ({len(detected_methods)}):")
    for method in detected_methods:
        print(f"  - {method}")

    return results


def evasion_example():
    """Sandbox detection with behavioral adaptation."""
    print("\n" + "=" * 70)
    print("SANDBOX EVASION WITH BEHAVIORAL ADAPTATION")
    print("=" * 70)

    detector = SandboxDetector()
    results = detector.evade_with_behavioral_adaptation(aggressive=False)

    print(f"\nSandbox Detected: {results['sandbox_detected']}")
    print(f"Sandbox Type: {results['sandbox_type']}")
    print(f"Confidence: {results['confidence']:.2%}")

    if results['evasion_applied']:
        print("\nEvasion Applied: Yes")
        print(f"Techniques Used: {', '.join(results['evasion_techniques'])}")
        print(f"Behavioral Changes ({len(results['behavioral_changes'])}):")
        for change in results['behavioral_changes'][:5]:
            print(f"  - {change}")
        if len(results['behavioral_changes']) > 5:
            print(f"  ... and {len(results['behavioral_changes']) - 5} more")

        print(f"\nBypass Successful: {results['detection_bypassed']}")
    else:
        print("\nNo evasion needed - running in normal environment")

    return results


def new_detection_methods_example():
    """Demonstrate new detection methods."""
    print("\n" + "=" * 70)
    print("NEW DETECTION METHODS DEMONSTRATION")
    print("=" * 70)

    detector = SandboxDetector()

    print("\n1. Environment Variable Analysis")
    detected, confidence, details = detector._check_environment_variables()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    if details['suspicious_vars']:
        print(f"   Suspicious variables: {details['suspicious_vars'][:3]}")

    print("\n2. Parent Process Analysis")
    detected, confidence, details = detector._check_parent_process()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    print(f"   Parent Process: {details['parent_name']}")
    if details['parent_cmdline']:
        print(f"   Command Line: {details['parent_cmdline'][:60]}...")

    print("\n3. CPUID Hypervisor Detection")
    detected, confidence, details = detector._check_cpuid_hypervisor()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    print(f"   Hypervisor Present: {details['hypervisor_present']}")
    if details['hypervisor_vendor']:
        print(f"   Hypervisor Vendor: {details['hypervisor_vendor']}")

    print("\n4. MAC Address Fingerprinting")
    detected, confidence, details = detector._check_mac_address_artifacts()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    print(f"   Network Interfaces: {len(details['mac_addresses'])}")
    if details['suspicious_vendors']:
        print(f"   Suspicious Vendors: {details['suspicious_vendors']}")

    print("\n5. Browser Automation Detection")
    detected, confidence, details = detector._check_browser_automation()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    if details['detected_frameworks']:
        print(f"   Frameworks: {', '.join(details['detected_frameworks'])}")

    print("\n6. Advanced Timing Analysis")
    detected, confidence, details = detector._check_advanced_timing()
    print(f"   Detected: {detected} (Confidence: {confidence:.2%})")
    print(f"   Methods Checked: {', '.join(details['methods_checked'])}")
    if details['timing_anomalies']:
        print(f"   Anomalies: {details['timing_anomalies'][:2]}")


def sandbox_signatures_example():
    """Show available sandbox signatures."""
    print("\n" + "=" * 70)
    print("AVAILABLE SANDBOX SIGNATURES")
    print("=" * 70)

    detector = SandboxDetector()

    print(f"\nTotal Sandboxes: {len(detector.sandbox_signatures)}")
    print("\nSandbox Types:")

    for sandbox_name, sig_data in sorted(detector.sandbox_signatures.items()):
        sig_count = sum(len(v) for v in sig_data.values() if isinstance(v, list))
        print(f"  - {sandbox_name.ljust(20)} ({sig_count} signatures)")

    print("\nNew Sandboxes Added:")
    new_sandboxes = ['hatching_triage', 'intezer', 'virustotal', 'browserstack']
    for sandbox in new_sandboxes:
        if sandbox in detector.sandbox_signatures:
            sig_data = detector.sandbox_signatures[sandbox]
            print(f"  ✓ {sandbox}")
            if sig_data.get('environment_vars'):
                print(f"    Env Vars: {', '.join(sig_data['environment_vars'])}")
            if sig_data.get('network'):
                print(f"    Networks: {', '.join(sig_data['network'])}")


def code_generation_example():
    """Generate C code for sandbox evasion."""
    print("\n" + "=" * 70)
    print("CODE GENERATION FOR EVASION")
    print("=" * 70)

    detector = SandboxDetector()
    evasion_code = detector.generate_sandbox_evasion()

    print("\nGenerated C Code (first 500 chars):")
    print("-" * 70)
    print(evasion_code[:500])
    print("...")
    print("-" * 70)

    lines = evasion_code.count('\n')
    print(f"\nTotal Lines: {lines}")
    print("Language: C")


def main():
    """Run all examples."""
    logging.basicConfig(
        level=logging.WARNING,
        format='%(levelname)s | %(name)s | %(message)s'
    )

    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + "  INTELLICRACK SANDBOX DETECTION & EVASION EXAMPLES".center(68) + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)

    try:
        basic_detection_example()

        aggressive_detection_example()

        evasion_example()

        new_detection_methods_example()

        sandbox_signatures_example()

        code_generation_example()

        print("\n" + "=" * 70)
        print("ALL EXAMPLES COMPLETED SUCCESSFULLY")
        print("=" * 70)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
