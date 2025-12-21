#!/usr/bin/env python3
"""Simple test for multi-environment tester."""

import sys
import json
sys.path.insert(0, r'D:\Intellicrack')

from tests.validation_system.multi_environment_tester import (
    EnvironmentDetector, TestEnvironment, MultiEnvironmentTester
)

def main():
    print("Testing Multi-Environment Tester...")
    print("-" * 50)

    # Test environment detector
    detector = EnvironmentDetector()

    print("Environment Detection:")
    container_info = detector.detect_container()
    print(f"  Container: {container_info['is_container']} ({container_info['container_type']})")

    cloud_info = detector.detect_cloud_provider()
    print(f"  Cloud: {cloud_info['is_cloud']} ({cloud_info['provider']})")

    wsl_info = detector.detect_wsl()
    print(f"  WSL: {wsl_info['is_wsl']} (version {wsl_info['version']})")

    # Test multi-environment tester initialization
    print("\nMulti-Environment Tester:")
    tester = MultiEnvironmentTester(r"D:\Intellicrack\tests\validation_system")
    print(f"  Environments loaded: {len(tester.environments)}")
    print(f"  Test suite loaded: {len(tester.test_suite)}")

    # Show first 3 environments
    print("\nConfigured Environments:")
    for env in tester.environments[:3]:
        print(f"  - {env.name} ({env.environment_type})")
        print(f"    OS: {env.platform_os}, Arch: {env.architecture}")
        print(f"    Tags: {', '.join(env.tags)}")

    # Run compatibility check
    print("\nCompatibility Check:")
    compat_report = tester.run_compatibility_check()
    current = compat_report['current_environment']
    print(f"  Current OS: {current['os']}")
    print(f"  Current Arch: {current['architecture']}")
    print(f"  Is VM: {current['is_vm']}")

    compatible_count = sum(bool(c['compatible'])
                       for c in compat_report['compatibility_matrix'])
    print(f"\n  Compatible environments: {compatible_count}/{len(tester.environments)}")

    print("\nOK Multi-Environment Tester Test Complete!")

if __name__ == "__main__":
    main()
