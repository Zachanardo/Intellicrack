#!/usr/bin/env python3
"""
Basic validation test for NetworkTrafficAnalyzer to ensure it loads and initializes properly.
"""

import sys
import traceback
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_basic_imports():
    """Test basic imports work."""
    try:
        from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer
        print("OK Successfully imported NetworkTrafficAnalyzer")
        return True
    except Exception as e:
        print(f"FAIL Failed to import NetworkTrafficAnalyzer: {e}")
        traceback.print_exc()
        return False

def test_basic_initialization():
    """Test basic analyzer initialization."""
    try:
        from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

        # Test with default config
        analyzer = NetworkTrafficAnalyzer()
        print("OK Successfully created analyzer with default config")

        # Test with custom config
        config = {
            "capture_file": "test.pcap",
            "max_packets": 100,
            "filter": "tcp",
            "visualization_dir": "test_viz"
        }

        analyzer2 = NetworkTrafficAnalyzer(config=config)
        print("OK Successfully created analyzer with custom config")

        # Test key attributes exist
        required_attrs = ['start_capture', 'stop_capture', 'analyze_traffic', 'get_results', 'generate_report']
        for attr in required_attrs:
            if hasattr(analyzer, attr):
                print(f"OK Has required method: {attr}")
            else:
                print(f"FAIL Missing required method: {attr}")
                return False

        # Test license patterns loaded
        if hasattr(analyzer, 'license_patterns') and len(analyzer.license_patterns) > 0:
            print(f"OK License patterns loaded: {len(analyzer.license_patterns)} patterns")
        else:
            print("FAIL License patterns not loaded")
            return False

        # Test license ports loaded
        if hasattr(analyzer, 'license_ports') and len(analyzer.license_ports) > 0:
            print(f"OK License ports loaded: {len(analyzer.license_ports)} ports")
        else:
            print("FAIL License ports not loaded")
            return False

        return True

    except Exception as e:
        print(f"FAIL Failed basic initialization: {e}")
        traceback.print_exc()
        return False

def test_packet_processing():
    """Test basic packet processing functionality."""
    try:
        from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

        analyzer = NetworkTrafficAnalyzer()

        # Test packet processing with license pattern
        test_packet = b"\x00" * 20 + b"FLEXLM_LICENSE_CHECK" + b"\x00" * 50
        analyzer._process_captured_packet(test_packet)
        print("OK Successfully processed packet with license pattern")

        # Test analysis functionality
        results = analyzer.analyze_traffic()
        if results is not None:
            print("OK Traffic analysis completed successfully")
            print(f"  - Total packets: {results.get('total_packets', 0)}")
            print(f"  - Total connections: {results.get('total_connections', 0)}")
            print(f"  - License connections: {results.get('license_connections', 0)}")
        else:
            print("FAIL Traffic analysis returned None")
            return False

        return True

    except Exception as e:
        print(f"FAIL Failed packet processing test: {e}")
        traceback.print_exc()
        return False

def test_results_functionality():
    """Test get_results functionality."""
    try:
        from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer

        analyzer = NetworkTrafficAnalyzer()

        # Add some test data
        analyzer.packets = [
            {
                'timestamp': 1234567890.0,
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 12345,
                'dst_port': 27000,
                'size': 100,
                'connection_id': 'test_conn',
                'payload': None
            }
        ]

        analyzer.connections = {
            'test_conn': {
                'src_ip': '10.0.0.1',
                'dst_ip': '10.0.0.2',
                'src_port': 12345,
                'dst_port': 27000,
                'bytes_sent': 1000,
                'bytes_received': 2000,
                'start_time': 1234567890.0,
                'last_time': 1234567920.0,
                'is_license': True,
                'packets': []
            }
        }

        results = analyzer.get_results()

        if results is not None:
            print("OK get_results() returned valid data")

            required_keys = ['packets_analyzed', 'protocols_detected', 'suspicious_traffic', 'statistics']
            for key in required_keys:
                if key in results:
                    print(f"OK Results contain key: {key}")
                else:
                    print(f"FAIL Results missing key: {key}")
                    return False

            # Check statistics
            stats = results.get('statistics', {})
            expected_stats = ['capture_duration', 'packets_per_second', 'total_bytes', 'unique_ips']
            for stat in expected_stats:
                if stat in stats:
                    print(f"OK Statistics contain: {stat}")
                else:
                    print(f"FAIL Statistics missing: {stat}")

        else:
            print("FAIL get_results() returned None")
            return False

        return True

    except Exception as e:
        print(f"FAIL Failed results functionality test: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all basic validation tests."""
    print("Running NetworkTrafficAnalyzer basic validation tests...")
    print("=" * 60)

    tests = [
        ("Import Test", test_basic_imports),
        ("Initialization Test", test_basic_initialization),
        ("Packet Processing Test", test_packet_processing),
        ("Results Functionality Test", test_results_functionality)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 30)

        try:
            if test_func():
                print(f"OK {test_name} PASSED")
                passed += 1
            else:
                print(f"FAIL {test_name} FAILED")
                failed += 1
        except Exception as e:
            print(f"FAIL {test_name} FAILED with exception: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
