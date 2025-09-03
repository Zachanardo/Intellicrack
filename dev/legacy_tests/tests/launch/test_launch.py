#!/usr/bin/env python3
import sys
import traceback
import pytest


class TestLaunch:
    """Test launch functionality."""

    def test_launch_import(self):
        """Test that launch function can be imported without errors."""
        from intellicrack.ui.main_app import launch
        assert callable(launch)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="GUI launch tests skipped on Windows due to display issues"
    )
    def test_launch_execution(self):
        """Test launch execution (skipped on Windows)."""
        try:
            from intellicrack.ui.main_app import launch
            result = launch()
            assert result is not None
        except Exception as e:
            pytest.fail(f"Launch failed: {e}")
