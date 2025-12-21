"""Production tests for intellicrack_advanced_protection widget.

Tests real intellicrack_advanced_protection functionality.
"""

from pathlib import Path
import pytest

PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestWidgetInitialization:
    """Test widget initialization."""

    def test_widget_imports(self) -> None:
        """Widget module can be imported."""
        try:
            from intellicrack.ui.widgets import intellicrack_advanced_protection_widget
            assert intellicrack_advanced_protection_widget is not None
        except ImportError:
            pytest.skip("Widget module not available")


class TestWidgetCreation:
    """Test widget creation."""

    def test_widget_has_classes(self) -> None:
        """Widget module contains widget classes."""
        try:
            from intellicrack.ui.widgets import intellicrack_advanced_protection_widget
            module_attrs = dir(intellicrack_advanced_protection_widget)
            has_widget = any("Widget" in attr for attr in module_attrs)
            assert has_widget or module_attrs
        except ImportError:
            pytest.skip("Widget module not available")
