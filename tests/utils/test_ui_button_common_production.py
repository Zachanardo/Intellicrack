"""Production-ready tests for UI Button Common - Button utility validation.

This module validates ui_button_common utility functionality including:
- Button creation with callbacks
- Button styling application
- Special styling for specific button types
- Layout integration
- Widget reference storage
- Error handling for missing PyQt6
"""

from typing import Any, Callable, cast

import pytest
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QPushButton

from intellicrack.utils.ui.ui_button_common import (
    PYQT_AVAILABLE,
    add_extra_buttons,
    get_button_style,
)

# Type alias for button callback list to match add_extra_buttons signature
ButtonCallbackList = list[tuple[str, Callable[..., object]]]


class FakeCallback:
    """Test double for button callbacks that tracks invocation."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_count: int = 0

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.called = True
        self.call_count += 1
        return None


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
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 1
        assert "Test Button" in buttons
        assert isinstance(buttons["Test Button"], QPushButton)
        assert layout.count() == 1

    def test_add_multiple_buttons(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons adds multiple buttons to layout."""
        callback1 = FakeCallback()
        callback2 = FakeCallback()
        callback3 = FakeCallback()
        extra_buttons: ButtonCallbackList = [
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

        def callback(*args: object, **kwargs: object) -> object:
            nonlocal callback_triggered
            callback_triggered = True
            return None

        extra_buttons: ButtonCallbackList = [("Test Button", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Test Button"]
        assert isinstance(button, QPushButton)
        button.click()
        assert callback_triggered

    def test_analyze_binary_button_special_styling(self, layout: QHBoxLayout) -> None:
        """Analyze Binary button receives special styling."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Analyze Binary", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Analyze Binary"]
        assert isinstance(button, QPushButton)
        style = button.styleSheet()
        assert "#2196F3" in style
        assert "background-color" in style
        assert "font-weight: bold" in style

    def test_regular_button_no_special_styling(self, layout: QHBoxLayout) -> None:
        """Regular buttons do not receive special styling."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Regular Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Regular Button"]
        assert isinstance(button, QPushButton)
        style = button.styleSheet()
        assert style == ""

    def test_widget_refs_stores_analyze_button(self, layout: QHBoxLayout) -> None:
        """widget_refs stores Analyze Binary button reference."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Analyze Binary", callback)]
        widget_refs: dict[str, Any] = {}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert "analyze_btn" in widget_refs
        assert widget_refs["analyze_btn"] is buttons["Analyze Binary"]

    def test_widget_refs_stores_extra_buttons(self, layout: QHBoxLayout) -> None:
        """widget_refs stores extra button references."""
        callback1 = FakeCallback()
        callback2 = FakeCallback()
        extra_buttons: ButtonCallbackList = [
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
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Custom Label", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        button = buttons["Custom Label"]
        assert isinstance(button, QPushButton)
        assert button.text() == "Custom Label"

    def test_multiple_button_callbacks_independent(self, layout: QHBoxLayout) -> None:
        """Multiple button callbacks work independently."""
        callback1_triggered = False
        callback2_triggered = False

        def callback1(*args: object, **kwargs: object) -> object:
            nonlocal callback1_triggered
            callback1_triggered = True
            return None

        def callback2(*args: object, **kwargs: object) -> object:
            nonlocal callback2_triggered
            callback2_triggered = True
            return None

        extra_buttons: ButtonCallbackList = [
            ("Button 1", callback1),
            ("Button 2", callback2),
        ]
        buttons = add_extra_buttons(layout, extra_buttons)

        button1 = buttons["Button 1"]
        assert isinstance(button1, QPushButton)
        button1.click()
        assert callback1_triggered
        assert not callback2_triggered

        button2 = buttons["Button 2"]
        assert isinstance(button2, QPushButton)
        button2.click()
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

    def test_add_buttons_requires_pyqt(self, layout: QHBoxLayout, monkeypatch: pytest.MonkeyPatch) -> None:
        """add_extra_buttons returns empty dict when PyQt unavailable."""
        monkeypatch.setattr("intellicrack.utils.ui.ui_button_common.PYQT_AVAILABLE", False)
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)
        assert buttons == {}


class TestButtonIntegrationScenarios:
    """Test button utilities in realistic integration scenarios."""

    def test_header_with_analyze_and_custom_buttons(self, layout: QHBoxLayout) -> None:
        """Header can have Analyze Binary and custom buttons."""
        analyze_callback = FakeCallback()
        custom_callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [
            ("Analyze Binary", analyze_callback),
            ("Export Results", custom_callback),
        ]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert len(buttons) == 2
        assert "Analyze Binary" in buttons
        assert "Export Results" in buttons

        analyze_btn = buttons["Analyze Binary"]
        assert isinstance(analyze_btn, QPushButton)
        analyze_btn.click()
        assert analyze_callback.called

        export_btn = buttons["Export Results"]
        assert isinstance(export_btn, QPushButton)
        export_btn.click()
        assert custom_callback.called

    def test_button_creation_with_widget_tracking(self, layout: QHBoxLayout) -> None:
        """Button creation tracks references for later access."""
        callback1 = FakeCallback()
        callback2 = FakeCallback()
        extra_buttons: ButtonCallbackList = [
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
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [
            ("First", callback),
            ("Second", callback),
            ("Third", callback),
        ]

        buttons = add_extra_buttons(layout, extra_buttons)

        item0 = layout.itemAt(0)
        assert item0 is not None
        widget0 = item0.widget()
        assert isinstance(widget0, QPushButton)
        assert widget0.text() == "First"

        item1 = layout.itemAt(1)
        assert item1 is not None
        widget1 = item1.widget()
        assert isinstance(widget1, QPushButton)
        assert widget1.text() == "Second"

        item2 = layout.itemAt(2)
        assert item2 is not None
        widget2 = item2.widget()
        assert isinstance(widget2, QPushButton)
        assert widget2.text() == "Third"


class TestButtonEdgeCases:
    """Test button utility edge cases and error handling."""

    def test_button_with_special_characters(self, layout: QHBoxLayout) -> None:
        """Button text with special characters handled correctly."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test & Button <>&", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert "Test & Button <>&" in buttons
        button = buttons["Test & Button <>&"]
        assert isinstance(button, QPushButton)
        assert button.text() == "Test & Button <>&"

    def test_button_with_unicode(self, layout: QHBoxLayout) -> None:
        """Button text with unicode characters handled correctly."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Analyze 分析", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert "Analyze 分析" in buttons

    def test_button_with_very_long_text(self, layout: QHBoxLayout) -> None:
        """Button with very long text handled correctly."""
        callback = FakeCallback()
        long_text = "A" * 100
        extra_buttons: ButtonCallbackList = [(long_text, callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        assert long_text in buttons

    def test_widget_refs_none(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons handles None widget_refs."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test", callback)]

        buttons = add_extra_buttons(layout, extra_buttons, None)

        assert len(buttons) == 1

    def test_widget_refs_without_extra_buttons_dict(self, layout: QHBoxLayout) -> None:
        """add_extra_buttons handles widget_refs without extra_buttons dict."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Regular Button", callback)]
        widget_refs: dict[str, Any] = {}

        buttons = add_extra_buttons(layout, extra_buttons, widget_refs)

        assert len(buttons) == 1


class TestButtonStylingConsistency:
    """Test button styling consistency and application."""

    def test_analyze_binary_style_applied_correctly(self, layout: QHBoxLayout) -> None:
        """Analyze Binary button style is applied correctly."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Analyze Binary", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)
        button = buttons["Analyze Binary"]
        assert isinstance(button, QPushButton)

        expected_style = get_button_style("Analyze Binary")
        assert button.styleSheet() == expected_style

    def test_style_consistency_across_multiple_calls(self, layout: QHBoxLayout) -> None:
        """Button style is consistent across multiple function calls."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Analyze Binary", callback)]

        buttons1 = add_extra_buttons(layout, extra_buttons)
        button1 = buttons1["Analyze Binary"]
        assert isinstance(button1, QPushButton)
        style1 = button1.styleSheet()

        layout2 = QHBoxLayout()
        buttons2 = add_extra_buttons(layout2, extra_buttons)
        button2 = buttons2["Analyze Binary"]
        assert isinstance(button2, QPushButton)
        style2 = button2.styleSheet()

        assert style1 == style2


class TestButtonFunctionalityVerification:
    """Test that buttons created function correctly."""

    def test_button_click_executes_callback(self, layout: QHBoxLayout) -> None:
        """Button click executes provided callback."""
        executed = False
        data = {"value": 0}

        def callback(*args: object, **kwargs: object) -> object:
            nonlocal executed
            executed = True
            data["value"] = 42
            return None

        extra_buttons: ButtonCallbackList = [("Action Button", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        action_btn = buttons["Action Button"]
        assert isinstance(action_btn, QPushButton)
        action_btn.click()

        assert executed
        assert data["value"] == 42

    def test_button_click_with_arguments(self, layout: QHBoxLayout) -> None:
        """Button callback with captured arguments works correctly."""
        result = None

        def make_callback(value: int) -> Callable[..., object]:
            def callback(*args: object, **kwargs: object) -> object:
                nonlocal result
                result = value * 2
                return None

            return callback

        callback = make_callback(21)
        extra_buttons: ButtonCallbackList = [("Calculate", callback)]
        buttons = add_extra_buttons(layout, extra_buttons)

        calc_btn = buttons["Calculate"]
        assert isinstance(calc_btn, QPushButton)
        calc_btn.click()

        assert result == 42

    def test_button_enabled_by_default(self, layout: QHBoxLayout) -> None:
        """Buttons are enabled by default."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test Button", callback)]

        buttons = add_extra_buttons(layout, extra_buttons)

        test_btn = buttons["Test Button"]
        assert isinstance(test_btn, QPushButton)
        assert test_btn.isEnabled()


class TestButtonLayoutIntegration:
    """Test button integration with Qt layouts."""

    def test_buttons_added_to_layout(self, layout: QHBoxLayout) -> None:
        """Buttons are properly added to provided layout."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [
            ("Button 1", callback),
            ("Button 2", callback),
        ]

        add_extra_buttons(layout, extra_buttons)

        assert layout.count() == 2

    def test_layout_widgets_are_buttons(self, layout: QHBoxLayout) -> None:
        """Layout items are QPushButton instances."""
        callback = FakeCallback()
        extra_buttons: ButtonCallbackList = [("Test", callback)]

        add_extra_buttons(layout, extra_buttons)

        item = layout.itemAt(0)
        assert item is not None
        widget = item.widget()
        assert isinstance(widget, QPushButton)

    def test_multiple_layouts_independent(self) -> None:
        """Buttons in different layouts are independent."""
        layout1 = QHBoxLayout()
        layout2 = QHBoxLayout()
        callback = FakeCallback()

        extra_buttons: ButtonCallbackList = [("Test", callback)]

        buttons1 = add_extra_buttons(layout1, extra_buttons)
        buttons2 = add_extra_buttons(layout2, extra_buttons)

        assert layout1.count() == 1
        assert layout2.count() == 1
        assert buttons1["Test"] is not buttons2["Test"]
