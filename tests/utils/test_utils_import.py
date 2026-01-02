#!/usr/bin/env python
"""Test utils import after disabling tool_wrappers."""

import pytest
import os



class TestUtilsImport:
    """Test utils import functionality."""

    def setup_method(self) -> None:
        """Set up environment variables before each test."""
        os.environ.setdefault("OMP_NUM_THREADS", "1")
        os.environ.setdefault("MKL_NUM_THREADS", "1")
        os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

    def test_utils_import(self) -> None:
        """Test that utils module can be imported successfully."""
        import intellicrack.utils
        assert intellicrack.utils is not None
        assert hasattr(intellicrack.utils, '__version__')

    def test_utils_basic_functionality(self) -> None:
        """Test basic utils functions are available."""
        import intellicrack.utils

        # Test basic functionality
        assert hasattr(intellicrack.utils, 'logger') or hasattr(intellicrack.utils, 'get_logger')
        # At least one logging method should be available
