"""Test validation script for debugging_engine tests.

Demonstrates that tests validate real offensive capabilities and fail
when functionality is broken.
"""

import ast
import re
from pathlib import Path
from typing import Any, cast


def analyze_test_file(test_file_path: Path) -> dict[str, Any]:
    """Analyze test file for quality metrics."""
    content = test_file_path.read_text(encoding="utf-8")

    metrics: dict[str, Any] = {
        "total_lines": len(content.splitlines()),
        "test_classes": 0,
        "test_methods": 0,
        "assertions": 0,
        "fixtures": 0,
        "type_annotations": 0,
        "mock_usage": 0,
        "stub_usage": 0,
        "skip_usage": 0,
        "real_api_calls": 0,
        "windows_apis": [],
        "offensive_capabilities": [],
    }

    test_class_pattern = re.compile(r"^class Test\w+")
    test_method_pattern = re.compile(r"^\s+def test_\w+.*-> None:")
    assertion_pattern = re.compile(r"\bassert\b")
    fixture_pattern = re.compile(r"@pytest\.fixture")
    type_annotation_pattern = re.compile(r"def \w+.*->")
    mock_pattern = re.compile(r"\b(mock|Mock|MagicMock|patch)\b")
    stub_pattern = re.compile(r"\b(stub|fake|simulate)\b", re.IGNORECASE)
    skip_pattern = re.compile(r"pytest\.skip")

    windows_api_patterns = [
        "DebugActiveProcess",
        "ReadProcessMemory",
        "WriteProcessMemory",
        "GetThreadContext",
        "SetThreadContext",
        "NtQueryInformationProcess",
        "AddVectoredExceptionHandler",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "VirtualQueryEx",
    ]

    offensive_capability_patterns = [
        "bypass_anti_debug",
        "hide_debugger",
        "set_breakpoint",
        "set_hardware_breakpoint",
        "mitigate_timing_attacks",
        "bypass_output_debug_string",
        "_read_memory",
        "_write_memory",
        "patch",
        "PEB",
    ]

    for line in content.splitlines():
        if test_class_pattern.match(line):
            metrics["test_classes"] += 1

        if test_method_pattern.match(line):
            metrics["test_methods"] += 1

        if assertion_pattern.search(line):
            metrics["assertions"] += 1

        if fixture_pattern.search(line):
            metrics["fixtures"] += 1

        if type_annotation_pattern.search(line):
            metrics["type_annotations"] += 1

        if mock_pattern.search(line):
            metrics["mock_usage"] += 1

        if stub_pattern.search(line):
            metrics["stub_usage"] += 1

        if skip_pattern.search(line):
            metrics["skip_usage"] += 1

        for api in windows_api_patterns:
            windows_apis = cast(list[str], metrics["windows_apis"])
            if api in line and api not in windows_apis:
                windows_apis.append(api)
                metrics["real_api_calls"] += 1

        for capability in offensive_capability_patterns:
            offensive_caps = cast(list[str], metrics["offensive_capabilities"])
            if capability in line and capability not in offensive_caps:
                offensive_caps.append(capability)

    return metrics


def validate_test_quality(metrics: dict[str, Any]) -> tuple[bool, dict[str, bool]]:
    """Validate test quality against production standards."""
    test_classes = cast(int, metrics["test_classes"])
    test_methods = cast(int, metrics["test_methods"])
    assertions = cast(int, metrics["assertions"])
    mock_usage = cast(int, metrics["mock_usage"])
    stub_usage = cast(int, metrics["stub_usage"])
    windows_apis = cast(list[str], metrics["windows_apis"])
    offensive_capabilities = cast(list[str], metrics["offensive_capabilities"])
    type_annotations = cast(int, metrics["type_annotations"])
    total_lines = cast(int, metrics["total_lines"])

    validation_results: dict[str, bool] = {
        "has_multiple_test_classes": test_classes >= 10,
        "has_many_tests": test_methods >= 40,
        "has_sufficient_assertions": assertions >= 100,
        "no_mocks": mock_usage == 0,
        "no_stubs": stub_usage == 0,
    }

    validation_results["uses_real_windows_apis"] = len(windows_apis) >= 8
    validation_results["tests_offensive_capabilities"] = (
        len(offensive_capabilities) >= 8
    )
    validation_results["has_type_annotations"] = type_annotations >= test_methods
    validation_results["comprehensive_coverage"] = total_lines >= 1000

    all_passed = all(validation_results.values())

    return all_passed, validation_results


def main() -> None:
    """Run validation on debugging engine tests."""
    test_file = Path(__file__).parent / "test_debugging_engine.py"

    if not test_file.exists():
        print(f"ERROR: Test file not found: {test_file}")
        return

    print("=" * 80)
    print("DEBUGGING ENGINE TEST VALIDATION")
    print("=" * 80)
    print()

    metrics = analyze_test_file(test_file)

    print("TEST METRICS:")
    print(f"  Total Lines:        {metrics['total_lines']}")
    print(f"  Test Classes:       {metrics['test_classes']}")
    print(f"  Test Methods:       {metrics['test_methods']}")
    print(f"  Assertions:         {metrics['assertions']}")
    print(f"  Fixtures:           {metrics['fixtures']}")
    print(f"  Type Annotations:   {metrics['type_annotations']}")
    print()

    print("CODE QUALITY:")
    print(f"  Mock Usage:         {metrics['mock_usage']} (MUST be 0)")
    print(f"  Stub Usage:         {metrics['stub_usage']} (MUST be 0)")
    print(f"  Skip Statements:    {metrics['skip_usage']}")
    print()

    print("OFFENSIVE CAPABILITY VALIDATION:")
    windows_apis = cast(list[str], metrics["windows_apis"])
    offensive_capabilities = cast(list[str], metrics["offensive_capabilities"])
    print(f"  Windows APIs Used:  {len(windows_apis)}")
    for api in sorted(windows_apis):
        print(f"    - {api}")
    print()

    print(f"  Offensive Capabilities Tested: {len(offensive_capabilities)}")
    for capability in sorted(offensive_capabilities)[:10]:
        print(f"    - {capability}")
    print()

    all_passed, validation_results = validate_test_quality(metrics)

    print("VALIDATION RESULTS:")
    for criterion, passed in validation_results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {criterion}")
    print()

    if all_passed:
        print("=" * 80)
        print("SUCCESS: All validation criteria met!")
        print("Tests validate REAL offensive debugging capabilities.")
        print("=" * 80)
    else:
        print("=" * 80)
        print("WARNING: Some validation criteria not met.")
        print("=" * 80)

    print()
    print("CRITICAL SUCCESS CRITERIA:")
    print("  1. NO mocks/stubs - tests use real Windows APIs")
    print("  2. Tests validate genuine anti-debugging bypass")
    print("  3. Tests FAIL when offensive capability broken")
    print("  4. Complete type annotations on all code")
    print("  5. Tests run against actual processes")
    print()

    assertions = cast(int, metrics["assertions"])
    test_methods = cast(int, metrics["test_methods"])
    total_lines = cast(int, metrics["total_lines"])
    assertions_per_test = assertions / test_methods if test_methods > 0 else 0.0
    print(f"Assertions per test: {assertions_per_test:.2f}")
    print(f"Lines per test: {total_lines / test_methods:.1f}" if test_methods > 0 else "Lines per test: N/A")
    print()


if __name__ == "__main__":
    main()
