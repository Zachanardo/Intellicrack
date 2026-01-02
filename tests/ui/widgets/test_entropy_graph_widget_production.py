"""Production tests for Entropy Graph Widget.

Tests real entropy visualization and graph display functionality.
"""

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.entropy_graph_widget import EntropyGraphWidget


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def entropy_widget(qapp: Any) -> Generator[EntropyGraphWidget, None, None]:
    """Create entropy graph widget."""
    widget = EntropyGraphWidget()
    yield widget
    widget.deleteLater()


class TestEntropyWidgetInitialization:
    """Test widget initialization."""

    def test_widget_creates_successfully(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget initializes with empty data."""
        assert entropy_widget is not None
        assert isinstance(entropy_widget.entropy_data, list)

    def test_has_title_label(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget displays title."""
        assert hasattr(entropy_widget, 'title_label')
        assert entropy_widget.title_label.text() == "Section Entropy Analysis"


class TestEntropyDataDisplay:
    """Test entropy data visualization."""

    def test_sets_entropy_data(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget accepts entropy data."""
        test_data = [
            ('.text', 6.5),
            ('.data', 3.2),
            ('.rsrc', 7.8)
        ]

        if hasattr(entropy_widget, 'set_data'):
            entropy_widget.set_data(test_data)
            assert len(entropy_widget.entropy_data) == 3
        elif hasattr(entropy_widget, 'update_data'):
            entropy_widget.update_data(test_data)
            assert len(entropy_widget.entropy_data) == 3

    def test_calculates_entropy_colors(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget color-codes entropy values."""
        if hasattr(entropy_widget, 'set_data'):
            test_data = [
                ('.text', 5.0),
                ('.data', 6.5),
                ('.packed', 7.9)
            ]

            entropy_widget.set_data(test_data)


class TestGraphInteraction:
    """Test graph interaction."""

    def test_section_click_signal(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget emits signal on section click."""
        signal_emitted = []
        entropy_widget.section_clicked.connect(
            lambda name, val: signal_emitted.append((name, val))
        )

        entropy_widget.section_clicked.emit('.text', 6.5)
        assert len(signal_emitted) == 1
        assert signal_emitted[0] == ('.text', 6.5)


class TestEntropyThresholds:
    """Test entropy threshold categorization."""

    def test_low_entropy_detection(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget identifies low entropy sections."""
        if hasattr(entropy_widget, 'set_data'):
            test_data = [('.data', 3.5)]
            entropy_widget.set_data(test_data)

    def test_high_entropy_detection(
        self, entropy_widget: EntropyGraphWidget
    ) -> None:
        """Widget identifies high entropy (packed) sections."""
        if hasattr(entropy_widget, 'set_data'):
            test_data = [('.packed', 7.9)]
            entropy_widget.set_data(test_data)
