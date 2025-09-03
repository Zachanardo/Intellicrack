#!/usr/bin/env python3
"""Test script for environment validator."""

import sys
from tests.validation_system.environment_validator import HardwareValidator

def main():
    print("Testing Environment Validator...")
    print("-" * 50)

    # Test the hardware validator
    validator = HardwareValidator()
    hardware_info = validator.collect_hardware_info()

    print("Hardware Information:")
    print(f"  CPU Model: {hardware_info.cpu_model}")
    print(f"  CPU Cores: {hardware_info.cpu_cores}")
    print(f"  CPU Features: {len(hardware_info.cpu_features)} features detected")
    if hardware_info.cpu_features:
        print(f"    Sample features: {hardware_info.cpu_features[:3]}")
    print(f"  RAM: {hardware_info.ram_gb} GB")
    print(f"  Motherboard: {hardware_info.motherboard_vendor} {hardware_info.motherboard_model}")
    print(f"  BIOS Version: {hardware_info.bios_version}")
    print(f"  System UUID: {hardware_info.system_uuid}")
    print(f"  Is Virtualized: {hardware_info.is_virtualized}")
    print(f"  Hypervisor Present: {hardware_info.hypervisor_present}")
    print(f"  VM Artifacts Found: {len(hardware_info.vm_artifacts)}")
    if hardware_info.vm_artifacts:
        print(f"    Artifacts: {hardware_info.vm_artifacts}")

    print("\nVM Detection:")
    print(f"  Is VM: {validator.is_virtual_machine()}")

    print("\nEnvironment Validation:")
    validation_result = validator.validate_environment()
    print(f"  Is Valid: {validation_result['is_valid']}")
    print(f"  Score: {validation_result['score']}/100")
    print(f"  Issues Found: {len(validation_result['issues'])}")
    if validation_result['issues']:
        print("  Issues:")
        for issue in validation_result['issues']:
            print(f"    - {issue}")

    print("\nMulti-Environment Testing Matrix:")
    test_matrix = validator.get_test_environments()
    print(f"  Environments to test: {len(test_matrix)}")
    for env in test_matrix[:3]:  # Show first 3
        print(f"    - {env['name']}: {env['description']}")

    print("\n✅ Environment Validator Test Complete!")

if __name__ == "__main__":
    main()
