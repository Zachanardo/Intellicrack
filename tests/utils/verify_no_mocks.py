#!/usr/bin/env python3
"""Verify that no test files use mocks or fake data.
This script enforces the REAL DATA ONLY testing principle.
"""

import os
import re
import sys
from pathlib import Path

# Patterns that indicate mock usage
MOCK_PATTERNS = [
    # Direct mock imports
    r"from\s+unittest\.mock\s+import",
    r"from\s+mock\s+import",
    r"import\s+unittest\.mock",
    r"import\s+mock",
    # Mock creation
    r"Mock\s*\(",
    r"MagicMock\s*\(",
    r"PropertyMock\s*\(",
    r"AsyncMock\s*\(",
    r"patch\s*\(",
    r"@patch",
    # Mock configuration
    r"return_value\s*=",
    r"side_effect\s*=",
    r"\.assert_called",
    r"\.assert_not_called",
    r"\.assert_any_call",
    r"\.call_count",
    # Fake data indicators
    r"fake_[a-zA-Z_]+\s*=",
    r"dummy_[a-zA-Z_]+\s*=",
    r"mock_[a-zA-Z_]+\s*=",
    r"placeholder_[a-zA-Z_]+\s*=",
    # Common test doubles
    r"class\s+Fake[A-Z]",
    r"class\s+Mock[A-Z]",
    r"class\s+Stub[A-Z]",
    r"class\s+Dummy[A-Z]",
    # Hardcoded test data
    r'["\']test123["\']',
    r'["\']example\.com["\']',
    r'["\']foo@bar\.com["\']',
    r'["\']placeholder["\']',
    r'["\']todo["\']',
    r'["\']fixme["\']',
]

# Files to exclude from checking
EXCLUDE_FILES = [
    "conftest.py",
    "__init__.py",
    "base_test.py",  # Base test class is allowed to mention mocks in validation
]

# Directories to exclude
EXCLUDE_DIRS = [
    "__pycache__",
    ".pytest_cache",
    "legacy_tests",
]


def find_mock_usage(file_path: Path) -> list[tuple[int, str, str]]:
    """Find all mock usage in a file.

    Returns list of (line_number, line_content, pattern_matched)
    """
    violations = []

    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            for pattern in MOCK_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append((line_num, line.strip(), pattern))
                    break
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return violations


def scan_test_directory(test_dir: Path) -> dict:
    """Scan entire test directory for mock usage.

    Returns dict of {file_path: [(line_num, line, pattern), ...]}
    """
    all_violations = {}

    for root, dirs, files in os.walk(test_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            if not file.endswith(".py"):
                continue

            if file in EXCLUDE_FILES:
                continue

            file_path = Path(root) / file
            violations = find_mock_usage(file_path)

            if violations:
                all_violations[str(file_path)] = violations

    return all_violations


def print_report(violations: dict) -> int:
    """Print violation report and return exit code."""
    if not violations:
        print("✅ SUCCESS: No mock usage found in tests!")
        print("All tests appear to use REAL data as required.")
        return 0

    print("❌ FAILURE: Mock usage detected in test files!")
    print("=" * 80)
    print("The following files violate the REAL DATA ONLY principle:")
    print("=" * 80)

    total_violations = 0

    for file_path, file_violations in violations.items():
        print(f"\n📄 {file_path}")
        print(f"   Found {len(file_violations)} violations:")

        for line_num, line, _pattern in file_violations[:5]:  # Show first 5
            print(f"   Line {line_num}: {line}")

        if len(file_violations) > 5:
            print(f"   ... and {len(file_violations) - 5} more violations")

        total_violations += len(file_violations)

    print("\n" + "=" * 80)
    print(f"Total files with violations: {len(violations)}")
    print(f"Total violations found: {total_violations}")
    print("=" * 80)
    print("\n⚠️  All tests MUST use REAL data, not mocks!")
    print("Replace mock usage with:")
    print("- Real binary files from tests/fixtures/binaries/")
    print("- Real network captures from tests/fixtures/network_captures/")
    print("- Real API responses (with test API keys)")
    print("- Real exploit payloads (in sandboxed environment)")

    return 1


def main():
    """Main entry point."""
    # Find test directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    test_dir = project_root / "tests"

    if not test_dir.exists():
        print(f"Error: Test directory not found at {test_dir}")
        return 1

    print(f"Scanning {test_dir} for mock usage...")
    print("This may take a moment...\n")

    violations = scan_test_directory(test_dir)
    return print_report(violations)


if __name__ == "__main__":
    sys.exit(main())
