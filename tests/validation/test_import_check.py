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
        print("✅ Main module imports successful")

        print("Testing BinarySimilaritySearch instantiation...")
        search_engine = BinarySimilaritySearch()
        print("✅ BinarySimilaritySearch instantiation successful")

        print("Testing factory function...")
        factory_engine = create_similarity_search()
        print("✅ Factory function successful")

        print("Testing test base import...")
        from tests.base_test import IntellicrackTestBase
        print("✅ Test base import successful")

        print("Testing pytest import...")
        import pytest
        print("✅ Pytest import successful")

        print("\n=== All imports successful! ===")
        return True

    except Exception as e:
        print(f"❌ Import failed: {e}")
        print("Traceback:")
        traceback.print_exc()
        return False

def check_test_file():
    """Check if test file exists and can be parsed."""
    print("\n=== Test File Check ===")

    test_file = Path("tests/unit/core/analysis/test_binary_similarity_search.py")
    if not test_file.exists():
        print(f"❌ Test file not found: {test_file}")
        return False

    print(f"✅ Test file exists: {test_file}")

    try:
        with open(test_file, 'r') as f:
            content = f.read()

        print(f"Test file size: {len(content)} characters")
        print(f"Test file lines: {len(content.splitlines())}")

        # Check for basic test structure
        if "class TestBinarySimilaritySearch" in content:
            print("✅ Test class found")
        else:
            print("❌ Test class not found")

        if "def test_" in content:
            test_count = content.count("def test_")
            print(f"✅ Found {test_count} test methods")
        else:
            print("❌ No test methods found")

        return True

    except Exception as e:
        print(f"❌ Error reading test file: {e}")
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
            print(f"✅ {dep}")
        except ImportError as e:
            print(f"❌ {dep}: {e}")

if __name__ == "__main__":
    success = True

    success &= test_imports()
    success &= check_test_file()
    check_dependencies()

    print(f"\n=== Final Result: {'SUCCESS' if success else 'FAILED'} ===")
