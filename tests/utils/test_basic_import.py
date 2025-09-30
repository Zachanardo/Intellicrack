#!/usr/bin/env python
"""Test most basic imports."""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")


class TestBasicImport:
    """Test basic import functionality."""

    def test_logger_import(self):
        """Test that logger can be imported successfully."""
        from intellicrack.utils.logger import logger
        assert logger is not None
