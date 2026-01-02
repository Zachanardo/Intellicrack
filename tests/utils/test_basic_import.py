#!/usr/bin/env python
"""Test most basic imports."""

import pytest


class TestBasicImport:
    """Test basic import functionality."""

    def test_logger_import(self) -> None:
        """Test that logger can be imported successfully."""
        from intellicrack.utils.logger import logger
        assert logger is not None
