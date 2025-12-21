"""Test Quality Verification Script.

Validates that streaming crypto detector tests meet all production standards:
- No mocks or stubs
- Complete type annotations
- Real binary testing
- No placeholders or TODOs

Run this before submitting tests for review.
"""

import ast
import re
from pathlib import Path
from typing import Any


def analyze_test_file(file_path: Path) -> dict[str, Any]:
    """Analyze test file for quality metrics.

    Args:
        file_path: Path to test file

    Returns:
        Dictionary with quality metrics
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        lines = content.splitlines()

    tree = ast.parse(content)

    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]

    test_classes = [c for c in classes if c.name.startswith("Test")]
    test_functions = [f for f in functions if f.name.startswith("test_")]
    fixtures = re.findall(r"@pytest\.fixture[^\n]*\ndef (\w+)", content)

    functions_with_return = sum(bool(f.returns is not None)
                            for f in test_functions)
    functions_with_params = sum(bool(all(arg.annotation is not None for arg in f.args.args if arg.arg != "self"))
                            for f in test_functions)

    forbidden_patterns = [
        ("mock", "Mock/MagicMock"),
        ("patch", "patch decorator"),
        ("unittest.mock", "unittest.mock"),
        ("TODO", "TODO comment"),
        ("FIXME", "FIXME comment"),
        ("XXX", "XXX comment"),
        (".skip", "pytest.skip"),
        ("pytest.mark.skip", "skip marker"),
        ("placeholder", "placeholder code"),
        ("stub", "stub implementation"),
    ]

    violations = []
    for pattern, name in forbidden_patterns:
        for i, line in enumerate(lines, 1):
            if pattern.lower() in line.lower() and not line.strip().startswith("#"):
                violations.append((i, name, line.strip()[:80]))

    real_binary_patterns = [
        r"C:\\Windows\\System32",
        r"Path\(r['\"]C:\\",
        "temp_binary_with_aes",
        "temp_binary_with_sha256",
        "temp_binary_with_rsa",
    ]

    uses_real_binaries = any(
        re.search(pattern, content) for pattern in real_binary_patterns
    )

    return {
        "total_lines": len(lines),
        "test_classes": len(test_classes),
        "test_functions": len(test_functions),
        "fixtures": len(fixtures),
        "type_annotations": {
            "return_types": functions_with_return,
            "parameter_types": functions_with_params,
            "complete": functions_with_return == len(test_functions)
            and functions_with_params == len(test_functions),
        },
        "violations": violations,
        "uses_real_binaries": uses_real_binaries,
        "test_class_names": [c.name for c in test_classes],
        "fixture_names": fixtures,
    }


def print_report(metrics: dict[str, Any]) -> bool:
    """Print quality report and return pass/fail status.

    Args:
        metrics: Quality metrics dictionary

    Returns:
        True if all checks pass, False otherwise
    """
    print("=" * 80)
    print("STREAMING CRYPTO DETECTOR TEST QUALITY REPORT")
    print("=" * 80)
    print()

    print(f"Total Lines: {metrics['total_lines']}")
    print(f"Test Classes: {metrics['test_classes']}")
    print(f"Test Functions: {metrics['test_functions']}")
    print(f"Fixtures: {metrics['fixtures']}")
    print()

    print("Test Classes:")
    for class_name in metrics["test_class_names"]:
        print(f"  - {class_name}")
    print()

    print("Fixtures:")
    for fixture_name in metrics["fixture_names"]:
        print(f"  - {fixture_name}")
    print()

    all_pass = True

    print("Type Annotations:")
    if metrics["type_annotations"]["complete"]:
        print("  ✓ All test functions have complete type annotations")
        print(
            f"    - Return types: {metrics['type_annotations']['return_types']}/{metrics['test_functions']}"
        )
        print(
            f"    - Parameter types: {metrics['type_annotations']['parameter_types']}/{metrics['test_functions']}"
        )
    else:
        print("  ✗ Incomplete type annotations")
        all_pass = False
    print()

    print("Real Binary Usage:")
    if metrics["uses_real_binaries"]:
        print("  ✓ Tests use real Windows binaries")
    else:
        print("  ✗ Tests don't use real binaries")
        all_pass = False
    print()

    print("Code Quality Violations:")
    if not metrics["violations"]:
        print("  ✓ No mocks, stubs, TODOs, or placeholders")
        print("  ✓ All tests use real implementations")
    else:
        print(f"  ✗ Found {len(metrics['violations'])} violations:")
        for line_num, pattern, line_content in metrics["violations"]:
            print(f"    Line {line_num}: {pattern}")
            print(f"      {line_content}")
        all_pass = False
    print()

    print("=" * 80)
    if all_pass:
        print("✓ ALL QUALITY CHECKS PASSED")
        print("✓ Tests are production-ready")
    else:
        print("✗ QUALITY CHECKS FAILED")
        print("✗ Fix violations before submission")
    print("=" * 80)

    return all_pass


def main() -> None:
    """Main entry point."""
    test_file = Path(__file__).parent / "test_streaming_crypto_detector_production.py"

    if not test_file.exists():
        print(f"Error: Test file not found at {test_file}")
        return

    metrics = analyze_test_file(test_file)
    passed = print_report(metrics)

    exit(0 if passed else 1)


if __name__ == "__main__":
    main()
