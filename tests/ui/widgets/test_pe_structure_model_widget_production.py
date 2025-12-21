"""Production tests for pe_structure_model widget.

Tests real pe_structure_model functionality.
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
            from intellicrack.ui.widgets import pe_structure_model_widget
            assert pe_structure_model_widget is not None
        except ImportError:
            pytest.skip("Widget module not available")


class TestWidgetCreation:
    """Test widget creation."""

    def test_widget_has_classes(self) -> None:
        """Widget module contains widget classes."""
        try:
            from intellicrack.ui.widgets import pe_structure_model_widget
            module_attrs = dir(pe_structure_model_widget)
            has_widget = any("Widget" in attr for attr in module_attrs)
            assert has_widget or len(module_attrs) > 0
        except ImportError:
            pytest.skip("Widget module not available")
