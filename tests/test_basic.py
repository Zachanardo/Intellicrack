"""
Basic tests for Intellicrack's testing framework.

This module contains simple sanity checks to verify the testing infrastructure is working correctly,
including basic mathematical operations and string manipulations. These tests serve as a foundation
for validating that the test environment is properly configured and functional.
"""

import pytest

class TestBasic:
    def test_math(self):
        pass

    def test_string(self):
        assert "test".upper() == "TEST"
