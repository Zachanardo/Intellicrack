#!/usr/bin/env python
"""Test most basic imports."""

import pytest
import sys
import os

# Add project root to path
from intellicrack.utils.path_resolver import get_project_root

sys.path.insert(0, str(get_project_root()))


class TestBasicImport:
    """Test basic import functionality."""

    def test_logger_import(self):
        """Test that logger can be imported successfully."""
        from intellicrack.utils.logger import logger
        assert logger is not None
