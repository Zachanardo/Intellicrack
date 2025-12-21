#!/usr/bin/env python3
"""
Simple import check for binary_similarity_search module and tests.
"""

import sys
import traceback
from pathlib import Path

def test_imports():
    """Test if all required imports work."""
    print("=== Import Check for Binary Similarity Search ===")

    try:
        print("Testing main module import...")
        from intellicrack.core.analysis.binary_similarity_search import BinarySimilaritySearch, create_similarity_search
        print("OK Main module imports successful")

        print("Testing BinarySimilaritySearch instantiation...")
        search_engine = BinarySimilaritySearch()
        print("OK BinarySimilaritySearch instantiation successful")

        print("Testing factory function...")
        factory_engine = create_similarity_search()
        print("OK Factory function successful")

        print("Testing test base import...")
        from tests.base_test import IntellicrackTestBase
        print("OK Test base import successful")

        print("Testing pytest import...")
        import pytest
        print("OK Pytest import successful")

        print("\n=== All imports successful! ===")
        return True

    except Exception as e:
        print(f"FAIL Import failed: {e}")
        print("Traceback:")
        traceback.print_exc()
        return False

def check_test_file():
    """Check if test file exists and can be parsed."""
    print("\n=== Test File Check ===")

    test_file = Path("tests/unit/core/analysis/test_binary_similarity_search.py")
    if not test_file.exists():
        print(f"FAIL Test file not found: {test_file}")
        return False

    print(f"OK Test file exists: {test_file}")

    try:
        content = Path(test_file).read_text()
        print(f"Test file size: {len(content)} characters")
        print(f"Test file lines: {len(content.splitlines())}")

        # Check for basic test structure
        if "class TestBinarySimilaritySearch" in content:
            print("OK Test class found")
        else:
            print("FAIL Test class not found")

        if "def test_" in content:
            test_count = content.count("def test_")
            print(f"OK Found {test_count} test methods")
        else:
            print("FAIL No test methods found")

        return True

    except Exception as e:
        print(f"FAIL Error reading test file: {e}")
        return False

def check_dependencies():
    """Check for test dependencies."""
    print("\n=== Dependency Check ===")

    dependencies = [
        'pytest', 'tempfile', 'json', 'os', 'pathlib'
    ]

    for dep in dependencies:
        try:
            __import__(dep)
            print(f"OK {dep}")
        except ImportError as e:
            print(f"FAIL {dep}: {e}")

if __name__ == "__main__":
    success = True

    success &= test_imports()
    success &= check_test_file()
    check_dependencies()

    print(f"\n=== Final Result: {'SUCCESS' if success else 'FAILED'} ===")
