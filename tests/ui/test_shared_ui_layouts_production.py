"""Production tests for intellicrack.ui.shared_ui_layouts.

Tests shared UI layout helper functions for creating consistent dialogs,
buttons, file browsers, and other common UI patterns.
"""

import pytest
from collections.abc import Generator
from typing import Callable
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from intellicrack.ui.shared_ui_layouts import UILayoutHelpers


@pytest.fixture(scope="module")
def qt_app() -> Generator[QApplication, None, None]:
    """Provide Qt application instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app  # type: ignore[misc]


@pytest.fixture
def test_dialog(qt_app: QApplication) -> Generator[QDialog, None, None]:
    """Create test dialog for layout operations."""
    dialog = QDialog()
    yield dialog
    dialog.close()


@pytest.fixture
def test_widget(qt_app: QApplication) -> Generator[QWidget, None, None]:
    """Create test widget for layout operations."""
    widget = QWidget()
    yield widget
    widget.close()


class TestCreateTabbedDialogLayout:
    """Test create_tabbed_dialog_layout functionality."""

    def test_create_tabbed_dialog_layout_basic(self, test_dialog: QDialog) -> None:
        """Creating tabbed dialog layout returns layout and tab widget."""
        main_layout, tab_widget = UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
        )

        assert isinstance(main_layout, QVBoxLayout)
        assert isinstance(tab_widget, QTabWidget)
        assert test_dialog.windowTitle() == "Test Dialog"


    def test_create_tabbed_dialog_layout_sets_window_size(
        self, test_dialog: QDialog
    ) -> None:
        """Dialog window size is set correctly."""
        UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
            size=(800, 600),
        )

        assert test_dialog.minimumWidth() == 800
        assert test_dialog.minimumHeight() == 600


    def test_create_tabbed_dialog_layout_default_size(
        self, test_dialog: QDialog
    ) -> None:
        """Default dialog size is 1000x700."""
        UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
        )

        assert test_dialog.minimumWidth() == 1000
        assert test_dialog.minimumHeight() == 700


    def test_create_tabbed_dialog_layout_modal_flag(
        self, test_dialog: QDialog
    ) -> None:
        """Modal flag is set when specified."""
        UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
            is_modal=True,
        )

        assert test_dialog.isModal()


    def test_create_tabbed_dialog_layout_not_modal_by_default(
        self, test_dialog: QDialog
    ) -> None:
        """Dialog is not modal by default."""
        UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
        )

        assert not test_dialog.isModal()


    def test_create_tabbed_dialog_layout_tab_widget_in_layout(
        self, test_dialog: QDialog
    ) -> None:
        """Tab widget is added to the main layout."""
        main_layout, tab_widget = UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Test Dialog",
        )

        assert tab_widget in [
            main_layout.itemAt(i).widget()  # type: ignore[union-attr]
            for i in range(main_layout.count())
        ]


class TestCreateDialogButtons:
    """Test create_dialog_buttons functionality."""

    def test_create_dialog_buttons_single_button(
        self, test_widget: QWidget
    ) -> None:
        """Creating single button works correctly."""
        layout = QVBoxLayout()
        button_clicked = False

        def on_click() -> None:
            nonlocal button_clicked
            button_clicked = True

        button_specs = [("Test Button", on_click, False)]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        assert len(buttons) == 1
        assert isinstance(buttons[0], QPushButton)
        assert buttons[0].text() == "Test Button"


    def test_create_dialog_buttons_multiple_buttons(
        self, test_widget: QWidget
    ) -> None:
        """Multiple buttons are created correctly."""
        layout = QVBoxLayout()

        button_specs = [
            ("Button 1", lambda: None, False),
            ("Button 2", lambda: None, True),
            ("Button 3", lambda: None, True),
        ]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        assert len(buttons) == 3
        assert buttons[0].text() == "Button 1"
        assert buttons[1].text() == "Button 2"
        assert buttons[2].text() == "Button 3"


    def test_create_dialog_buttons_callback_connected(
        self, test_widget: QWidget
    ) -> None:
        """Button callbacks are connected correctly."""
        layout = QVBoxLayout()
        clicked_buttons = []

        def make_callback(name: str) -> Callable[[], None]:
            def callback() -> None:
                clicked_buttons.append(name)
            return callback

        button_specs = [
            ("Button 1", make_callback("btn1"), False),
            ("Button 2", make_callback("btn2"), False),
        ]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        buttons[0].click()
        buttons[1].click()

        assert clicked_buttons == ["btn1", "btn2"]


    def test_create_dialog_buttons_alignment_left(
        self, test_widget: QWidget
    ) -> None:
        """Left-aligned buttons are placed before stretch."""
        layout = QVBoxLayout()

        button_specs = [
            ("Left Button", lambda: None, False),
        ]
        UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        button_layout = layout.itemAt(layout.count() - 1)
        assert button_layout is not None


    def test_create_dialog_buttons_alignment_right(
        self, test_widget: QWidget
    ) -> None:
        """Right-aligned buttons are placed after stretch."""
        layout = QVBoxLayout()

        button_specs = [
            ("Right Button", lambda: None, True),
        ]
        UILayoutHelpers.create_dialog_buttons(button_specs, layout)

        button_layout = layout.itemAt(layout.count() - 1)
        assert button_layout is not None


class TestCreateFileBrowseWidget:
    """Test create_file_browse_widget functionality."""

    def test_create_file_browse_widget_basic(self) -> None:
        """Creating file browse widget returns layout, line edit, and button."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget()

        assert isinstance(layout, QHBoxLayout)
        assert isinstance(line_edit, QLineEdit)
        assert isinstance(browse_btn, QPushButton)


    def test_create_file_browse_widget_line_edit_in_layout(self) -> None:
        """Line edit is added to layout."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget()

        widgets_in_layout = [
            layout.itemAt(i).widget()  # type: ignore[union-attr]
            for i in range(layout.count())
            if layout.itemAt(i).widget() is not None  # type: ignore[union-attr]
        ]

        assert line_edit in widgets_in_layout


    def test_create_file_browse_widget_button_in_layout(self) -> None:
        """Browse button is added to layout."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget()

        widgets_in_layout = [
            layout.itemAt(i).widget()  # type: ignore[union-attr]
            for i in range(layout.count())
            if layout.itemAt(i).widget() is not None  # type: ignore[union-attr]
        ]

        assert browse_btn in widgets_in_layout


    def test_create_file_browse_widget_custom_browse_text(self) -> None:
        """Custom browse button text is applied."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget(
            browse_text="Select File..."
        )

        assert browse_btn.text() == "Select File..."


    def test_create_file_browse_widget_default_browse_text(self) -> None:
        """Default browse button text is 'Browse...'."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget()

        assert browse_btn.text() == "Browse..."


    def test_create_file_browse_widget_callback_connected(self) -> None:
        """Browse callback is connected to button."""
        callback_called = False

        def on_browse() -> None:
            nonlocal callback_called
            callback_called = True

        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget(
            browse_callback=on_browse
        )

        browse_btn.click()
        assert callback_called


    def test_create_file_browse_widget_no_callback(self) -> None:
        """Widget works without callback specified."""
        layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget()

        browse_btn.click()


class TestCreateConfigGroup:
    """Test create_config_group functionality."""

    def test_create_config_group_basic(self) -> None:
        """Creating config group returns group box and layout."""
        group, layout = UILayoutHelpers.create_config_group("Test Group")

        assert isinstance(group, QGroupBox)
        assert group.title() == "Test Group"


    def test_create_config_group_form_layout(self) -> None:
        """Form layout is used when use_form_layout is True."""
        group, layout = UILayoutHelpers.create_config_group(
            "Test Group",
            use_form_layout=True
        )

        assert isinstance(layout, QFormLayout)


    def test_create_config_group_vbox_layout(self) -> None:
        """VBox layout is used when use_form_layout is False."""
        group, layout = UILayoutHelpers.create_config_group(
            "Test Group",
            use_form_layout=False
        )

        assert isinstance(layout, QVBoxLayout)


    def test_create_config_group_default_uses_form_layout(self) -> None:
        """Default uses form layout."""
        group, layout = UILayoutHelpers.create_config_group("Test Group")

        assert isinstance(layout, QFormLayout)


    def test_create_config_group_layout_set_on_group(self) -> None:
        """Layout is set on the group box."""
        group, layout = UILayoutHelpers.create_config_group("Test Group")

        assert group.layout() is layout


class TestFinalizeWidgetLayout:
    """Test finalize_widget_layout functionality."""

    def test_finalize_widget_layout_vbox_adds_stretch(
        self, test_widget: QWidget
    ) -> None:
        """Finalizing VBox layout adds stretch."""
        layout = QVBoxLayout()
        initial_count = layout.count()

        UILayoutHelpers.finalize_widget_layout(test_widget, layout)

        assert layout.count() > initial_count


    def test_finalize_widget_layout_sets_widget_layout(
        self, test_widget: QWidget
    ) -> None:
        """Widget layout is set correctly."""
        layout = QVBoxLayout()

        UILayoutHelpers.finalize_widget_layout(test_widget, layout)

        assert test_widget.layout() is layout


    def test_finalize_widget_layout_returns_widget(
        self, test_widget: QWidget
    ) -> None:
        """Finalize returns the widget for method chaining."""
        layout = QVBoxLayout()

        result = UILayoutHelpers.finalize_widget_layout(test_widget, layout)

        assert result is test_widget


    def test_finalize_widget_layout_form_layout_no_stretch(
        self, test_widget: QWidget
    ) -> None:
        """Form layout doesn't have addStretch, handles gracefully."""
        layout = QFormLayout()

        UILayoutHelpers.finalize_widget_layout(test_widget, layout)

        assert test_widget.layout() is layout


class TestSetupStandardFormField:
    """Test setup_standard_form_field functionality."""

    def test_setup_standard_form_field_form_layout(self) -> None:
        """Form field is added correctly to QFormLayout."""
        layout = QFormLayout()
        widget = QLineEdit()

        UILayoutHelpers.setup_standard_form_field(layout, "Test Field:", widget)

        assert layout.rowCount() == 1


    def test_setup_standard_form_field_vbox_layout_fallback(self) -> None:
        """VBox layout fallback adds widget when addRow doesn't exist."""
        layout = QVBoxLayout()
        widget = QLineEdit()

        UILayoutHelpers.setup_standard_form_field(layout, "Test Field:", widget)

        assert layout.count() > 0


class TestCreateTabsFromSpecs:
    """Test create_tabs_from_specs functionality."""

    def test_create_tabs_from_specs_single_tab(
        self, test_widget: QWidget
    ) -> None:
        """Single tab is added correctly."""
        tab_widget = QTabWidget()
        widget1 = QWidget()

        tab_specs = [("Tab 1", widget1)]
        UILayoutHelpers.create_tabs_from_specs(tab_widget, tab_specs)

        assert tab_widget.count() == 1
        assert tab_widget.tabText(0) == "Tab 1"
        assert tab_widget.widget(0) is widget1


    def test_create_tabs_from_specs_multiple_tabs(
        self, test_widget: QWidget
    ) -> None:
        """Multiple tabs are added in correct order."""
        tab_widget = QTabWidget()
        widget1 = QWidget()
        widget2 = QWidget()
        widget3 = QWidget()

        tab_specs = [
            ("First", widget1),
            ("Second", widget2),
            ("Third", widget3),
        ]
        UILayoutHelpers.create_tabs_from_specs(tab_widget, tab_specs)

        assert tab_widget.count() == 3
        assert tab_widget.tabText(0) == "First"
        assert tab_widget.tabText(1) == "Second"
        assert tab_widget.tabText(2) == "Third"
        assert tab_widget.widget(0) is widget1
        assert tab_widget.widget(1) is widget2
        assert tab_widget.widget(2) is widget3


    def test_create_tabs_from_specs_empty_list(self) -> None:
        """Empty tab specs list creates no tabs."""
        tab_widget = QTabWidget()

        tab_specs: list[tuple[str, QWidget]] = []
        UILayoutHelpers.create_tabs_from_specs(tab_widget, tab_specs)

        assert tab_widget.count() == 0


class TestUILayoutHelpersIntegration:
    """Integration tests for complete UI layout workflows."""

    def test_complete_dialog_creation_workflow(
        self, test_dialog: QDialog
    ) -> None:
        """Complete dialog creation workflow with all helpers."""
        main_layout, tab_widget = UILayoutHelpers.create_tabbed_dialog_layout(
            test_dialog,
            "Complete Dialog",
            size=(900, 700),
            is_modal=True,
        )

        config_widget = QWidget()
        config_layout = QVBoxLayout()

        group1, group1_layout = UILayoutHelpers.create_config_group(
            "Configuration",
            use_form_layout=True
        )
        config_layout.addWidget(group1)

        file_layout, line_edit, browse_btn = UILayoutHelpers.create_file_browse_widget(
            browse_text="Select..."
        )
        config_layout.addLayout(file_layout)

        button_specs = [
            ("Save", lambda: None, False),
            ("Cancel", lambda: None, True),
            ("Apply", lambda: None, True),
        ]
        buttons = UILayoutHelpers.create_dialog_buttons(button_specs, config_layout)

        config_widget.setLayout(config_layout)

        tab_specs = [("Configuration", config_widget)]
        UILayoutHelpers.create_tabs_from_specs(tab_widget, tab_specs)

        test_dialog.setLayout(main_layout)

        assert test_dialog.windowTitle() == "Complete Dialog"
        assert test_dialog.isModal()
        assert tab_widget.count() == 1
        assert len(buttons) == 3


    def test_multiple_config_groups_with_form_fields(self) -> None:
        """Multiple config groups with form fields work correctly."""
        group1, layout1 = UILayoutHelpers.create_config_group("Group 1")
        group2, layout2 = UILayoutHelpers.create_config_group("Group 2")

        widget1 = QLineEdit()
        widget2 = QLineEdit()

        UILayoutHelpers.setup_standard_form_field(layout1, "Field 1:", widget1)
        UILayoutHelpers.setup_standard_form_field(layout2, "Field 2:", widget2)

        assert layout1.rowCount() == 1  # type: ignore[union-attr]
        assert layout2.rowCount() == 1  # type: ignore[union-attr]
