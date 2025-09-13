#!/usr/bin/env python3
"""
Quick validation test for beacon manager functionality
"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

def test_beacon_manager_import():
    """Test basic import functionality"""
    try:
        from intellicrack.core.c2.beacon_manager import BeaconManager
        print("✓ BeaconManager imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import BeaconManager: {e}")
        return False

def test_beacon_manager_basic_functionality():
    """Test basic BeaconManager functionality"""
    try:
        from intellicrack.core.c2.beacon_manager import BeaconManager

        # Create instance
        manager = BeaconManager()
        print("✓ BeaconManager instance created")

        # Test registration
        session_id = "test_session_001"
        config = {
            "beacon_interval": 60,
            "jitter_percent": 20,
            "client_info": {
                "hostname": "test-machine",
                "os": "Windows 10",
                "architecture": "x64"
            }
        }

        manager.register_session(session_id, config)
        print("✓ Session registered successfully")

        # Test beacon update
        beacon_data = {
            "system_status": {
                "cpu_percent": 25.0,
                "memory_percent": 45.0
            },
            "timestamp": 1234567890.0
        }

        manager.update_beacon(session_id, beacon_data)
        print("✓ Beacon updated successfully")

        # Test status retrieval
        status = manager.get_session_status(session_id)
        if status and status.get("session_id") == session_id:
            print("✓ Session status retrieved successfully")
        else:
            print("✗ Session status retrieval failed")
            return False

        # Test statistics
        stats = manager.get_statistics()
        if stats and "total_beacons" in stats:
            print("✓ Statistics retrieved successfully")
        else:
            print("✗ Statistics retrieval failed")
            return False

        print("✓ All basic functionality tests passed")
        return True

    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    """Run quick validation tests"""
    print("Running beacon manager validation tests...\n")

    success = True

    # Test import
    if not test_beacon_manager_import():
        success = False

    # Test functionality
    if not test_beacon_manager_basic_functionality():
        success = False

    print(f"\n{'='*50}")
    if success:
        print("✓ ALL TESTS PASSED - BeaconManager is functional")
    else:
        print("✗ SOME TESTS FAILED - Check errors above")
    print(f"{'='*50}")

    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
