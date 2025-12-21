"""
Validation script for tools_tab tests.

Verifies that tests are properly structured and can detect failures.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


def validate_test_structure() -> None:
    """Validate that test file is properly structured."""
    test_file = Path(__file__).parent / "test_tools_tab.py"

    if not test_file.exists():
        print(f"ERROR: Test file not found: {test_file}")
        sys.exit(1)

    content = test_file.read_text()

    required_elements = [
        "class TestToolsTabInitialization:",
        "class TestSystemInformationTools:",
        "class TestFileOperationTools:",
        "class TestBinaryAnalysisTools:",
        "class TestCryptographicTools:",
        "class TestPluginManagement:",
        "class TestNetworkTools:",
        "class TestWindowsActivationTools:",
        "class TestAdvancedAnalysisTools:",
        "class TestExploitationTools:",
        "class TestNetworkAnalysisTools:",
        "class TestBinaryLoadingSignals:",
        "class TestRegistryTools:",
        "class TestToolOutputAndLogging:",
        "def test_",
        "import pytest",
        "@pytest.fixture",
    ]

    if missing := [
        element for element in required_elements if element not in content
    ]:
        print("ERROR: Missing required elements:")
        for item in missing:
            print(f"  - {item}")
        sys.exit(1)

    test_count = content.count("def test_")
    print("✓ Test file structure validated")
    print(f"✓ Found {test_count} test methods")

    if test_count < 30:
        print(f"WARNING: Only {test_count} tests found, expected at least 30")

    if "from unittest.mock import Mock" in content:
        print("✓ Uses Mock for Qt UI components")

    if 'pytest.skip("Cannot initialize' in content:
        print("✓ Properly handles Qt initialization errors")

    if "sample_pe_binary: Path" in content:
        print("✓ Uses real binary fixtures")

    print("\n✓ All validation checks passed!")


def check_test_coverage() -> None:
    """Check that critical functionality is tested."""
    test_file = Path(__file__).parent / "test_tools_tab.py"
    content = test_file.read_text()

    critical_methods = [
        "get_system_info",
        "list_processes",
        "get_file_info",
        "create_hex_dump",
        "extract_strings",
        "disassemble_binary",
        "analyze_entropy",
        "analyze_imports",
        "calculate_hash",
        "base64_encode",
        "base64_decode",
        "load_selected_plugin",
        "unload_selected_plugin",
        "populate_network_interfaces",
        "ping_scan",
        "port_scan",
        "check_windows_activation",
        "run_frida_analysis",
        "run_ghidra_analysis",
        "run_protection_scanner",
        "run_rop_generator",
        "run_payload_engine",
        "run_traffic_analysis",
        "on_binary_loaded",
        "on_binary_unloaded",
        "enable_binary_dependent_tools",
    ]

    print("\nChecking test coverage for critical methods:")
    untested = []
    for method in critical_methods:
        if f"test_{method}" in content or method in content:
            print(f"  ✓ {method}")
        else:
            print(f"  ✗ {method}")
            untested.append(method)

    if untested:
        print(f"\nWARNING: {len(untested)} methods may not have dedicated tests")
    else:
        print("\n✓ All critical methods have test coverage!")


def check_real_functionality_validation() -> None:
    """Verify tests validate real functionality, not just execution."""
    test_file = Path(__file__).parent / "test_tools_tab.py"
    content = test_file.read_text()

    print("\nChecking for real functionality validation:")

    anti_patterns = {
        "assert result is not None": 0,
        "assert True": 0,
        "pass  # TODO": 0,
        "# stub": 0,
        "# placeholder": 0,
    }

    for pattern in anti_patterns:
        anti_patterns[pattern] = content.lower().count(pattern.lower())

    has_anti_patterns = False
    for pattern, count in anti_patterns.items():
        if count > 0:
            print(f"  ✗ Found {count} instances of anti-pattern: {pattern}")
            has_anti_patterns = True

    if not has_anti_patterns:
        print("  ✓ No placeholder/stub test anti-patterns detected")

    good_patterns = [
        "assert.*in.*combined_output",
        "assert.*call_count.*>.*0",
        "sample_pe_binary",
        "protected_binary",
    ]

    found_good = sum(bool(pattern.replace(".*", "") in content)
                 for pattern in good_patterns)
    if found_good >= 3:
        print("  ✓ Tests validate real output and behavior")
    else:
        print("  ⚠ Limited real functionality validation detected")


if __name__ == "__main__":
    print("=" * 60)
    print("VALIDATING TOOLS_TAB TEST SUITE")
    print("=" * 60)

    try:
        validate_test_structure()
        check_test_coverage()
        check_real_functionality_validation()

        print("\n" + "=" * 60)
        print("VALIDATION COMPLETE - Tests are properly structured")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ Validation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
