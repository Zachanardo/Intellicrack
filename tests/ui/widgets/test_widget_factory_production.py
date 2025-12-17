"""Production tests for widget factory.

Validates widget creation utilities including tree widgets, console editors,
input fields, button layouts, list widgets, and grouped widgets for
standardized UI component creation.
"""

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QFont, Qt
from intellicrack.ui.widgets.widget_factory import (
    create_button_layout,
    create_console_text_edit,
    create_grouped_widget,
    create_input_field,
    create_list_widget,
    create_standard_dialog_buttons,
    create_tree_widget,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_create_tree_widget_basic(qapp: QApplication) -> None:
    """Create tree widget with headers."""
    headers = ["Name", "Value", "Type"]

    tree = create_tree_widget(headers)

    assert tree is not None
    assert tree.headerItem() is not None
    for i, header in enumerate(headers):
        assert tree.headerItem().text(i) == header


def test_create_tree_widget_with_callback(qapp: QApplication) -> None:
    """Create tree widget with item changed callback."""
    call_count = [0]

    def callback() -> None:
        call_count[0] += 1

    tree = create_tree_widget(["Col1", "Col2"], item_changed_callback=callback)

    assert tree is not None


def test_create_console_text_edit_default(qapp: QApplication) -> None:
    """Create console text edit with defaults."""
    console = create_console_text_edit()

    assert console is not None
    assert console.isReadOnly() is True
    assert console.font().family() == "Consolas"
    assert console.font().pointSize() == 9


def test_create_console_text_edit_custom_size(qapp: QApplication) -> None:
    """Create console text edit with custom font size."""
    console = create_console_text_edit(font_size=12)

    assert console.font().pointSize() == 12


def test_create_console_text_edit_editable(qapp: QApplication) -> None:
    """Create console text edit as editable."""
    console = create_console_text_edit(read_only=False)

    assert console.isReadOnly() is False


def test_create_input_field_basic(qapp: QApplication) -> None:
    """Create basic input field."""
    field = create_input_field()

    assert field is not None
    assert field.text() == ""


def test_create_input_field_with_hint(qapp: QApplication) -> None:
    """Create input field with hint text."""
    hint = "Enter value here"

    field = create_input_field(hint_text=hint)

    assert field.placeholderText() == hint


def test_create_input_field_with_default(qapp: QApplication) -> None:
    """Create input field with default value."""
    default = "default_value"

    field = create_input_field(default_value=default)

    assert field.text() == default


def test_create_input_field_with_hint_and_default(qapp: QApplication) -> None:
    """Create input field with both hint and default value."""
    field = create_input_field(hint_text="Enter name", default_value="John")

    assert field.text() == "John"
    assert field.placeholderText() == "Enter name"


def test_create_button_layout_basic(qapp: QApplication) -> None:
    """Create button layout with multiple buttons."""
    clicked = [False, False]

    def callback1() -> None:
        clicked[0] = True

    def callback2() -> None:
        clicked[1] = True

    button_configs = [
        {"text": "Button 1", "callback": callback1},
        {"text": "Button 2", "callback": callback2},
    ]

    layout = create_button_layout(button_configs)

    assert layout is not None
    assert layout.count() >= 2


def test_create_button_layout_with_stretch(qapp: QApplication) -> None:
    """Create button layout with stretch enabled."""
    button_configs = [{"text": "OK", "callback": lambda: None}]

    layout = create_button_layout(button_configs, add_stretch=True)

    assert layout is not None
    assert layout.count() > 1


def test_create_button_layout_without_stretch(qapp: QApplication) -> None:
    """Create button layout without stretch."""
    button_configs = [{"text": "OK", "callback": lambda: None}]

    layout = create_button_layout(button_configs, add_stretch=False)

    assert layout is not None


def test_create_button_layout_empty_configs(qapp: QApplication) -> None:
    """Create button layout with empty configs."""
    layout = create_button_layout([])

    assert layout is not None


def test_create_list_widget_basic(qapp: QApplication) -> None:
    """Create basic list widget."""
    list_widget = create_list_widget()

    assert list_widget is not None
    assert list_widget.count() == 0


def test_create_list_widget_with_click_callback(qapp: QApplication) -> None:
    """Create list widget with item clicked callback."""
    clicked = [False]

    def callback() -> None:
        clicked[0] = True

    list_widget = create_list_widget(item_clicked_callback=callback)

    assert list_widget is not None


def test_create_list_widget_with_context_menu(qapp: QApplication) -> None:
    """Create list widget with context menu callback."""
    def context_callback() -> None:
        pass

    list_widget = create_list_widget(context_menu_callback=context_callback)

    assert list_widget is not None
    assert list_widget.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu


def test_create_grouped_widget_basic(qapp: QApplication) -> None:
    """Create grouped widget with title."""
    from intellicrack.handlers.pyqt6_handler import QLabel

    content = QLabel("Test content")
    title = "Test Group"

    group = create_grouped_widget(title, content)

    assert group is not None
    assert group.title() == title
    assert group.layout() is not None


def test_create_grouped_widget_contains_content(qapp: QApplication) -> None:
    """Create grouped widget contains provided content."""
    from intellicrack.handlers.pyqt6_handler import QPushButton

    button = QPushButton("Test")

    group = create_grouped_widget("Group", button)

    assert group.layout() is not None
    assert group.layout().count() > 0


def test_create_standard_dialog_buttons_basic(qapp: QApplication) -> None:
    """Create standard dialog buttons."""
    clicked = [False, False]

    def ok_callback() -> None:
        clicked[0] = True

    def cancel_callback() -> None:
        clicked[1] = True

    layout = create_standard_dialog_buttons(["OK", "Cancel"], [ok_callback, cancel_callback])

    assert layout is not None
    assert layout.count() >= 2


def test_create_standard_dialog_buttons_mismatched_lengths(qapp: QApplication) -> None:
    """Create standard dialog buttons raises error for mismatched lengths."""
    with pytest.raises(ValueError, match="Number of buttons must match"):
        create_standard_dialog_buttons(["OK", "Cancel"], [lambda: None])


def test_create_standard_dialog_buttons_empty(qapp: QApplication) -> None:
    """Create standard dialog buttons with empty lists."""
    layout = create_standard_dialog_buttons([], [])

    assert layout is not None


def test_create_standard_dialog_buttons_single(qapp: QApplication) -> None:
    """Create standard dialog buttons with single button."""
    layout = create_standard_dialog_buttons(["OK"], [lambda: None])

    assert layout is not None


def test_tree_widget_accepts_multiple_headers(qapp: QApplication) -> None:
    """Tree widget accepts multiple column headers."""
    headers = ["Col1", "Col2", "Col3", "Col4", "Col5"]

    tree = create_tree_widget(headers)

    assert tree.columnCount() == len(headers)


def test_console_text_edit_font_family(qapp: QApplication) -> None:
    """Console text edit uses monospace font."""
    console = create_console_text_edit()

    assert "Consolas" in console.font().family() or console.font().fixedPitch()


def test_input_field_accepts_user_input(qapp: QApplication) -> None:
    """Input field accepts and stores user input."""
    field = create_input_field()

    field.setText("user input")

    assert field.text() == "user input"


def test_button_layout_buttons_are_clickable(qapp: QApplication) -> None:
    """Button layout creates clickable buttons."""
    clicked = [False]

    def callback() -> None:
        clicked[0] = True

    button_configs = [{"text": "Click Me", "callback": callback}]

    layout = create_button_layout(button_configs)

    button = layout.itemAt(0).widget()
    assert button is not None

    button.click()

    assert clicked[0] is True


def test_list_widget_accepts_items(qapp: QApplication) -> None:
    """List widget accepts items."""
    from intellicrack.handlers.pyqt6_handler import QListWidgetItem

    list_widget = create_list_widget()

    list_widget.addItem(QListWidgetItem("Item 1"))
    list_widget.addItem(QListWidgetItem("Item 2"))

    assert list_widget.count() == 2


def test_grouped_widget_layout_type(qapp: QApplication) -> None:
    """Grouped widget uses vertical layout."""
    from intellicrack.handlers.pyqt6_handler import QLabel, QVBoxLayout

    content = QLabel("Content")

    group = create_grouped_widget("Title", content)

    assert isinstance(group.layout(), QVBoxLayout)


def test_console_text_edit_large_font_size(qapp: QApplication) -> None:
    """Console text edit handles large font sizes."""
    console = create_console_text_edit(font_size=24)

    assert console.font().pointSize() == 24


def test_console_text_edit_small_font_size(qapp: QApplication) -> None:
    """Console text edit handles small font sizes."""
    console = create_console_text_edit(font_size=6)

    assert console.font().pointSize() == 6


def test_input_field_clear_text(qapp: QApplication) -> None:
    """Input field text can be cleared."""
    field = create_input_field(default_value="initial")

    field.clear()

    assert field.text() == ""


def test_tree_widget_empty_headers(qapp: QApplication) -> None:
    """Tree widget handles empty headers list."""
    tree = create_tree_widget([])

    assert tree.columnCount() == 0


def test_button_layout_preserves_button_order(qapp: QApplication) -> None:
    """Button layout preserves button order."""
    button_configs = [
        {"text": "First", "callback": lambda: None},
        {"text": "Second", "callback": lambda: None},
        {"text": "Third", "callback": lambda: None},
    ]

    layout = create_button_layout(button_configs, add_stretch=False)

    first_button = layout.itemAt(0).widget()
    second_button = layout.itemAt(1).widget()
    third_button = layout.itemAt(2).widget()

    assert first_button.text() == "First"
    assert second_button.text() == "Second"
    assert third_button.text() == "Third"


def test_standard_dialog_buttons_have_stretch(qapp: QApplication) -> None:
    """Standard dialog buttons include stretch at start."""
    layout = create_standard_dialog_buttons(["OK"], [lambda: None])

    assert layout.count() >= 2


def test_list_widget_without_callbacks(qapp: QApplication) -> None:
    """List widget works without any callbacks."""
    list_widget = create_list_widget()

    assert list_widget is not None
    assert list_widget.count() == 0


def test_console_text_edit_accepts_text(qapp: QApplication) -> None:
    """Console text edit accepts and displays text."""
    console = create_console_text_edit(read_only=False)

    console.setPlainText("Console output line 1\nConsole output line 2")

    assert "line 1" in console.toPlainText()
    assert "line 2" in console.toPlainText()


def test_tree_widget_single_header(qapp: QApplication) -> None:
    """Tree widget handles single header column."""
    tree = create_tree_widget(["Single Column"])

    assert tree.columnCount() == 1
    assert tree.headerItem().text(0) == "Single Column"


def test_grouped_widget_title_display(qapp: QApplication) -> None:
    """Grouped widget displays title correctly."""
    from intellicrack.handlers.pyqt6_handler import QLabel

    title = "Custom Group Title"
    group = create_grouped_widget(title, QLabel())

    assert group.title() == title


def test_input_field_hint_persists_without_default(qapp: QApplication) -> None:
    """Input field hint text persists when no default value."""
    field = create_input_field(hint_text="Enter value")

    assert field.placeholderText() == "Enter value"
    assert field.text() == ""


def test_multiple_widget_creation_independence(qapp: QApplication) -> None:
    """Multiple widgets created independently."""
    field1 = create_input_field(default_value="Field 1")
    field2 = create_input_field(default_value="Field 2")

    assert field1.text() == "Field 1"
    assert field2.text() == "Field 2"

    field1.setText("Modified")

    assert field1.text() == "Modified"
    assert field2.text() == "Field 2"
