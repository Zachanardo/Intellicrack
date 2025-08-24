#!/usr/bin/env python
"""Minimal test to check application launch"""

import sys
import os
import pytest

# Configure TensorFlow to prevent GPU initialization issues
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'


class TestMinimalLaunch:
    """Minimal launch tests with environment configuration."""

    def test_qt_application_import(self):
        """Test that QApplication can be imported."""
        from intellicrack.ui.dialogs.common_imports import QApplication
        assert QApplication is not None

    def test_intellicrack_app_import(self):
        """Test that IntellicrackApp can be imported."""
        from intellicrack.ui.main_app import IntellicrackApp
        assert IntellicrackApp is not None

    @pytest.mark.skipif(
        sys.platform == "win32", 
        reason="GUI creation tests skipped on Windows due to display issues"
    )
    def test_qt_application_creation(self):
        """Test QApplication creation (skipped on Windows)."""
        from intellicrack.ui.dialogs.common_imports import QApplication
        app = QApplication(sys.argv)
        assert app is not None

    @pytest.mark.skipif(
        sys.platform == "win32", 
        reason="GUI window tests skipped on Windows due to display issues"
    )
    def test_intellicrack_app_creation(self):
        """Test IntellicrackApp creation (skipped on Windows)."""
        from intellicrack.ui.dialogs.common_imports import QApplication
        from intellicrack.ui.main_app import IntellicrackApp
        
        app = QApplication(sys.argv)
        window = IntellicrackApp()
        window.setWindowTitle("Intellicrack Test")
        window.resize(1200, 800)
        assert window is not None
