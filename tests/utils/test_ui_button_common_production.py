"""Production-ready tests for UI Button Common - Button utility validation.

This module validates ui_button_common utility functionality including:
- Button creation with callbacks
- Button styling application
- Special styling for specific button types
- Layout integration
- Widget reference storage
- Error handling for missing PyQt6
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QPushButton

from intellicrack.utils.ui.ui_button_common import (
    PYQT_AVAILABLE,
    add_extra_buttons,
    get_button_style,
)


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def layout(qapp: QApplication) -> QHBoxLayout:
    """Create QHBoxLayout for button testing."""
    return QHBoxLayout()


class TestAddExtraButtons:
    """Test add_extra_buttons functionality."""

    def test_add_single_button(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons adds single button to layout."""
        callback = MagicMock()
        extra_buttons = [("Test Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 1
        assert "Test Button" in buttons
        assert isinstance(buttons["Test Button"], QPushButton)
        assert layout.count() == 1

    def test_add_multiple_buttons(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons adds multiple buttons to layout."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        callback3 = MagicMock()
        extra_buttons = [
            ("Button 1", callback1),
            ("Button 2", callback2),
            ("Button 3", callback3),
        ]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 3
        assert "Button 1" in buttons
        assert "Button 2" in buttons
        assert "Button 3" in buttons
        assert layout.count() == 3

    def test_button_callback_connected(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons connects callback to button click."""
        callback_triggered = False

        def callback() -> None:
            nonlocal callback_triggered
            callback_triggered = True

        extra_buttons = [("Test Button", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        buttons["Test Button"].click()
        assert callback_triggered

    def test_analyze_binary_button_special_styling(self, layout: QHBoxLayout) -> None:
        """Analyze Binary button receives special styling."""
        callback = MagicMock()
        extra_buttons = [("Analyze Binary", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Analyze Binary"]
        style = button.styleSheet()
        assert "#2196F3" in style
        assert "background-color" in style
        assert "font-weight: bold" in style

    def test_regular_button_no_special_styling(self, layout: QHBoxLayout) -> None:
        """Regular buttons do not receive special styling."""
        callback = MagicMock()
        extra_buttons = [("Regular Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Regular Button"]
        style = button.styleSheet()
        assert style == ""

    def test_widget_refs_stores_analyze_button(self, layout: QHBoxLayout) -> None:
        """widget_refs stores Analyze Binary button reference."""
        callback = MagicMock()
        extra_buttons = [("Analyze Binary", callback)]
        widget_refs: dict[str, Any] = {}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert "analyze_btn" in widget_refs
        assert widget_refs["analyze_btn"] is buttons["Analyze Binary"]

    def test_widget_refs_stores_extra_buttons(self, layout: QHBoxLayout) -> None:
        """widget_refs stores extra button references."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        extra_buttons = [
            ("Button 1", callback1),
            ("Button 2", callback2),
        ]
        widget_refs: dict[str, Any] = {"extra_buttons": {}}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert "Button 1" in widget_refs["extra_buttons"]
        assert "Button 2" in widget_refs["extra_buttons"]

    def test_empty_buttons_list(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons handles empty button list."""
        extra_buttons: list[tuple[str, Any]] = []

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 0
        assert layout.count() == 0

    def test_button_text_set_correctly(self, layout: QHBoxLayout) -> None:
        """Button text is set to provided text."""
        callback = MagicMock()
        extra_buttons = [("Custom Label", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert buttons["Custom Label"].text() == "Custom Label"

    def test_multiple_button_callbacks_independent(self, layout: QHBoxLayout) -> None:
        """Multiple button callbacks work independently."""
        callback1_triggered = False
        callback2_triggered = False

        def callback1() -> None:
            nonlocal callback1_triggered
            callback1_triggered = True

        def callback2() -> None:
            nonlocal callback2_triggered
            callback2_triggered = True

        extra_buttons = [
            ("Button 1", callback1),
            ("Button 2", callback2),
        ]
        buttons = add_extra_buttons(layout, extra_buttons)

        buttons["Button 1"].click()
        assert callback1_triggered
        assert not callback2_triggered

        buttons["Button 2"].click()
        assert callback2_triggered


class TestGetButtonStyle:
    """Test get_button_style functionality."""

    def test_analyze_binary_button_style(self) -> None:
        """get_button_style returns correct style for Analyze Binary."""
        style = get_button_style("Analyze Binary")
        assert "#2196F3" in style
        assert "background-color" in style
        assert "color: white" in style
        assert "font-weight: bold" in style

    def test_regular_button_style(self) -> None:
        """get_button_style returns empty string for regular buttons."""
        style = get_button_style("Regular Button")
        assert style == ""

    def test_empty_button_text_style(self) -> None:
        """get_button_style handles empty button text."""
        style = get_button_style("")
        assert style == ""

    def test_case_sensitive_button_name(self) -> None:
        """get_button_style is case-sensitive for button names."""
        style = get_button_style("analyze binary")
        assert style == ""

        style = get_button_style("ANALYZE BINARY")
        assert style == ""


class TestPyQtAvailability:
    """Test PyQt6 availability handling."""

    def test_pyqt_available_flag_true(self) -> None:
        """PYQT_AVAILABLE flag is True when PyQt6 imported successfully."""
        assert PYQT_AVAILABLE is True

    def test_add_buttons_requires_pyqt(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons returns empty dict when PyQt unavailable."""
        with patch("intellicrack.utils.ui.ui_button_common.PYQT_AVAILABLE", False):
            callback = MagicMock()
            extra_buttons = [("Test", callback)]
            buttons = add_extra_buttons(layout, extra_buttons)
            assert buttons == {}


class TestButtonIntegrationScenarios:
    """Test button utilities in realistic integration scenarios."""

    def test_header_with_analyze_and_custom_buttons(self, layout: QHBoxLayout) -> None:
        """Header can have Analyze Binary and custom buttons."""
        analyze_callback = MagicMock()
        custom_callback = MagicMock()
        extra_buttons = [
            ("Analyze Binary", analyze_callback),
            ("Export Results", custom_callback),
        ]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 2
        assert "Analyze Binary" in buttons
        assert "Export Results" in buttons

        buttons["Analyze Binary"].click()
        assert analyze_callback.called

        buttons["Export Results"].click()
        assert custom_callback.called

    def test_button_creation_with_widget_tracking(self, layout: QHBoxLayout) -> None:
        """Button creation tracks references for later access."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        extra_buttons = [
            ("Analyze Binary", callback1),
            ("Custom Action", callback2),
        ]
        widget_refs: dict[str, Any] = {"extra_buttons": {}}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert "analyze_btn" in widget_refs
        assert "Custom Action" in widget_refs["extra_buttons"]
        assert widget_refs["analyze_btn"] is buttons["Analyze Binary"]

    def test_buttons_maintain_order(self, layout: QHBoxLayout) -> None:
        """Buttons are added to layout in order provided."""
        callback = MagicMock()
        extra_buttons = [
            ("First", callback),
            ("Second", callback),
            ("Third", callback),
        ]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert layout.itemAt(0).widget().text() == "First"
        assert layout.itemAt(1).widget().text() == "Second"
        assert layout.itemAt(2).widget().text() == "Third"


class TestButtonEdgeCases:
    """Test button utility edge cases and error handling."""

    def test_button_with_special_characters(self, layout: QHBoxLayout) -> None:
        """Button text with special characters handled correctly."""
        callback = MagicMock()
        extra_buttons = [("Test & Button <>&", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert "Test & Button <>&" in buttons
        assert buttons["Test & Button <>&"].text() == "Test & Button <>&"

    def test_button_with_unicode(self, layout: QHBoxLayout) -> None:
        """Button text with unicode characters handled correctly."""
        callback = MagicMock()
        extra_buttons = [("Analyze 分析", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert "Analyze 分析" in buttons

    def test_button_with_very_long_text(self, layout: QHBoxLayout) -> None:
        """Button with very long text handled correctly."""
        callback = MagicMock()
        long_text = "A" * 100
        extra_buttons = [(long_text, callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert long_text in buttons

    def test_widget_refs_none(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons handles None widget_refs."""
        callback = MagicMock()
        extra_buttons = [("Test", callback)]

        buttons = add_extra_buttons(layout, extra_buttons, None)

        assert len(buttons) == 1

    def test_widget_refs_without_extra_buttons_dict(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons handles widget_refs without extra_buttons dict."""
        callback = MagicMock()
        extra_buttons = [("Regular Button", callback)]
        widget_refs: dict[str, Any] = {}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert len(buttons) == 1


class TestButtonStylingConsistency:
    """Test button styling consistency and application."""

    def test_analyze_binary_style_applied_correctly(self, layout: QHBoxLayout) -> None:
        """Analyze Binary button style is applied correctly."""
        callback = MagicMock()
        extra_buttons = [("Analyze Binary", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)
        button = buttons["Analyze Binary"]

        expected_style = get_button_style("Analyze Binary")
        assert button.styleSheet() == expected_style

    def test_style_consistency_across_multiple_calls(self, layout: QHBoxLayout) -> None:
        """Button style is consistent across multiple function calls."""
        callback = MagicMock()
        extra_buttons = [("Analyze Binary", callback)]

        buttons1 = add_extra_buttons(layout, extra_buttons)
        style1 = buttons1["Analyze Binary"].styleSheet()

        layout2 = QHBoxLayout()
        buttons2 = add_extra_buttons(layout2, extra_buttons)
        style2 = buttons2["Analyze Binary"].styleSheet()

        assert style1 == style2


class TestButtonFunctionalityVerification:
    """Test that buttons created function correctly."""

    def test_button_click_executes_callback(self, layout: QHBoxLayout) -> None:
        """Button click executes provided callback."""
        executed = False
        data = {"value": 0}

        def callback() -> None:
            nonlocal executed
            executed = True
            data["value"] = 42

        extra_buttons = [("Action Button", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        buttons["Action Button"].click()

        assert executed
        assert data["value"] == 42

    def test_button_click_with_arguments(self, layout: QHBoxLayout) -> None:
        """Button callback with captured arguments works correctly."""
        result = None

        def make_callback(value: int) -> Any:
            def callback() -> None:
                nonlocal result
                result = value * 2

            return callback

        callback = make_callback(21)
        extra_buttons = [("Calculate", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        buttons["Calculate"].click()

        assert result == 42

    def test_button_enabled_by_default(self, layout: QHBoxLayout) -> None:
        """Buttons are enabled by default."""
        callback = MagicMock()
        extra_buttons = [("Test Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert buttons["Test Button"].isEnabled()


class TestButtonLayoutIntegration:
    """Test button integration with Qt layouts."""

    def test_buttons_added_to_layout(self, layout: QHBoxLayout) -> None:
        """Buttons are properly added to provided layout."""
        callback = MagicMock()
        extra_buttons = [
            ("Button 1", callback),
            ("Button 2", callback),
        ]

        add_extra_buttons(layout, extra_buttons)

        assert layout.count() == 2

    def test_layout_widgets_are_buttons(self, layout: QHBoxLayout) -> None:
        """Layout items are QPushButton instances."""
        callback = MagicMock()
        extra_buttons = [("Test", callback)]

        add_extra_buttons(layout, extra_buttons)

        widget = layout.itemAt(0).widget()
        assert isinstance(widget, QPushButton)

    def test_multiple_layouts_independent(self) -> None:
        """Buttons in different layouts are independent."""
        layout1 = QHBoxLayout()
        layout2 = QHBoxLayout()
        callback = MagicMock()

        extra_buttons = [("Test", callback)]

        buttons1 = add_extra_buttons(layout1, extra_buttons)
        buttons2 = add_extra_buttons(layout2, extra_buttons)

        assert layout1.count() == 1
        assert layout2.count() == 1
        assert buttons1["Test"] is not buttons2["Test"]
