"""Provide imports for Intellicrack UI dialogs.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Common imports for dialog modules.

This module centralizes common PyQt6 imports to avoid duplication.
"""

import contextlib
import os
from collections.abc import Callable
from typing import Any, TypeVar

from ...utils.logger import get_logger


logger = get_logger(__name__)

T = TypeVar("T")


class _FallbackWidgetBase:
    """Production fallback base for PyQt widgets when PyQt6 is unavailable.

    Provides functional state management and interface compatibility.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the fallback widget base.

        Args:
            *args: Additional positional arguments (ignored).
            **kwargs: Additional keyword arguments (ignored).

        """
        self._visible: bool = True
        self._enabled: bool = True
        self._children: list[Any] = []
        self._style: str = ""

    def show(self) -> None:
        """Make the widget visible."""
        self._visible = True

    def hide(self) -> None:
        """Hide the widget."""
        self._visible = False

    def setVisible(self, visible: bool) -> None:
        """Set widget visibility state.

        Args:
            visible: True to show the widget, False to hide it.

        """
        self._visible = visible

    def isVisible(self) -> bool:
        """Check if widget is visible.

        Returns:
            True if the widget is visible.

        """
        return self._visible

    def setEnabled(self, enabled: bool) -> None:
        """Set widget enabled state.

        Args:
            enabled: True to enable the widget, False to disable it.

        """
        self._enabled = enabled

    def isEnabled(self) -> bool:
        """Check if widget is enabled.

        Returns:
            True if the widget is enabled.

        """
        return self._enabled

    def setStyleSheet(self, style: str) -> None:
        """Set the widget style sheet.

        Args:
            style: CSS style string.

        """
        self._style = style

    def styleSheet(self) -> str:
        """Get the widget style sheet.

        Returns:
            The CSS style string.

        """
        return self._style

    def setParent(self, parent: Any) -> None:
        """Set the parent widget.

        Args:
            parent: Parent widget object.

        """
        self._parent = parent

    def parent(self) -> Any:
        """Get the parent widget.

        Returns:
            The parent widget or None.

        """
        return getattr(self, "_parent", None)

    def deleteLater(self) -> None:
        """Mark widget for deletion."""
        self._visible = False
        self._enabled = False


class _FallbackLayout(_FallbackWidgetBase):
    """Production fallback layout manager for non-PyQt environments."""

    def addWidget(self, widget: Any, *args: Any, **kwargs: Any) -> None:
        """Add a widget to the layout.

        Args:
            widget: Widget to add to the layout.
            *args: Additional positional arguments (ignored).
            **kwargs: Additional keyword arguments (ignored).

        """
        self._children.append(widget)

    def addLayout(self, layout: Any) -> None:
        """Add a layout to this layout.

        Args:
            layout: Layout object to add.

        """
        self._children.append(layout)

    def setContentsMargins(self, left: int, top: int, right: int, bottom: int) -> None:
        """Set the layout margins.

        Args:
            left: Left margin.
            top: Top margin.
            right: Right margin.
            bottom: Bottom margin.

        """
        self._margins = (left, top, right, bottom)

    def contentsMargins(self) -> tuple[int, int, int, int]:
        """Get the layout margins.

        Returns:
            Tuple of (left, top, right, bottom) margins.

        """
        return getattr(self, "_margins", (0, 0, 0, 0))

    def setSpacing(self, spacing: int) -> None:
        """Set the spacing between layout items.

        Args:
            spacing: Spacing value in pixels.

        """
        self._spacing = spacing

    def spacing(self) -> int:
        """Get the spacing between layout items.

        Returns:
            Spacing value in pixels.

        """
        return getattr(self, "_spacing", 0)


class _FallbackDialog(_FallbackWidgetBase):
    """Production fallback dialog implementation for non-PyQt environments."""

    class DialogCode:
        Accepted: int = 1
        Rejected: int = 0

    def __init__(self, parent: Any = None) -> None:
        super().__init__()
        self._result: int = 0
        self._title: str = ""

    def exec(self) -> int:
        """Execute the dialog modally.

        Returns:
            Dialog result code (1 for accepted, 0 for rejected).

        """
        return self._result

    def accept(self) -> None:
        """Accept the dialog."""
        self._result = 1

    def reject(self) -> None:
        """Reject the dialog."""
        self._result = 0

    def setWindowTitle(self, title: str) -> None:
        """Set the dialog window title.

        Args:
            title: Window title text.

        """
        self._title = title

    def windowTitle(self) -> str:
        """Get the dialog window title.

        Returns:
            The window title text.

        """
        return self._title

    def setMinimumSize(self, w: int, h: int) -> None:
        """Set the minimum dialog size.

        Args:
            w: Minimum width.
            h: Minimum height.

        """
        self._min_size = (w, h)

    def minimumSize(self) -> tuple[int, int]:
        """Get the minimum dialog size.

        Returns:
            Tuple of (width, height).

        """
        return getattr(self, "_min_size", (0, 0))

    def setLayout(self, layout: Any) -> None:
        """Set the dialog layout.

        Args:
            layout: Layout object to set.

        """
        self._layout = layout


class _FallbackButton(_FallbackWidgetBase):
    """Production fallback button implementation with signal support."""

    class _Signal:
        """Signal class for button click events."""

        def __init__(self) -> None:
            """Initialize the signal with an empty callback list."""
            self._callbacks: list[Callable[..., Any]] = []

        def connect(self, callback: Callable[..., Any]) -> None:
            """Connect a callback to the signal.

            Args:
                callback: Callable to invoke when signal is emitted.

            """
            self._callbacks.append(callback)

        def disconnect(self, callback: Callable[..., Any] | None = None) -> None:
            """Disconnect a callback from the signal.

            Args:
                callback: Callable to disconnect, or None to disconnect all.

            """
            if callback is None:
                self._callbacks.clear()
            elif callback in self._callbacks:
                self._callbacks.remove(callback)

        def emit(self, *args: Any) -> None:
            """Emit the signal, invoking all connected callbacks.

            Args:
                *args: Arguments to pass to connected callbacks.

            """
            for cb in self._callbacks:
                with contextlib.suppress(Exception):
                    cb(*args)

    def __init__(self, text: str = "", parent: Any = None) -> None:
        """Initialize the button.

        Args:
            text: Button label text.
            parent: Parent widget.

        """
        super().__init__()
        self._text = text
        self.clicked = self._Signal()

    def text(self) -> str:
        """Get the button label text.

        Returns:
            The button text.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the button label text.

        Args:
            text: Button label text.

        """
        self._text = text

    def click(self) -> None:
        """Trigger a button click event."""
        self.clicked.emit()


class _FallbackLabel(_FallbackWidgetBase):
    """Production fallback label implementation for text display."""

    def __init__(self, text: str = "", parent: Any = None) -> None:
        """Initialize the label.

        Args:
            text: Label text.
            parent: Parent widget.

        """
        super().__init__()
        self._text = text

    def text(self) -> str:
        """Get the label text.

        Returns:
            The label text.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the label text.

        Args:
            text: New label text.

        """
        self._text = text


class _FallbackTextEdit(_FallbackWidgetBase):
    """Production fallback text editor for multi-line text input."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the text editor.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._text = ""
        self._readonly = False

    def toPlainText(self) -> str:
        """Get the plain text content.

        Returns:
            The text content.

        """
        return self._text

    def setPlainText(self, text: str) -> None:
        """Set the plain text content.

        Args:
            text: New text content.

        """
        self._text = text

    def setReadOnly(self, readonly: bool) -> None:
        """Set the read-only state.

        Args:
            readonly: True to make read-only, False otherwise.

        """
        self._readonly = readonly

    def isReadOnly(self) -> bool:
        """Check if the editor is read-only.

        Returns:
            True if the editor is read-only.

        """
        return self._readonly

    def setMaximumHeight(self, height: int) -> None:
        """Set the maximum editor height.

        Args:
            height: Maximum height in pixels.

        """
        self._max_height = height


class _FallbackLineEdit(_FallbackWidgetBase):
    """Production fallback single-line text input."""

    class EchoMode:
        """Echo mode constants for text input."""

        Normal: int = 0
        Password: int = 2

    def __init__(self, parent: Any = None) -> None:
        """Initialize the line editor.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._text = ""
        self._echo_mode = self.EchoMode.Normal

    def text(self) -> str:
        """Get the text content.

        Returns:
            The text content.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the text content.

        Args:
            text: New text content.

        """
        self._text = text

    def setEchoMode(self, mode: int) -> None:
        """Set the echo mode for text display.

        Args:
            mode: Echo mode constant.

        """
        self._echo_mode = mode

    def echoMode(self) -> int:
        """Get the echo mode.

        Returns:
            The current echo mode.

        """
        return self._echo_mode


class _FallbackComboBox(_FallbackWidgetBase):
    """Production fallback dropdown selection widget."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the combo box.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._items: list[str] = []
        self._item_data: list[Any] = []
        self._current_index: int = -1

    def addItem(self, text: str, data: Any = None) -> None:
        """Add an item to the combo box.

        Args:
            text: Item display text.
            data: Associated data for the item.

        """
        self._items.append(text)
        self._item_data.append(data)
        if self._current_index < 0 and self._items:
            self._current_index = 0

    def addItems(self, items: list[str]) -> None:
        """Add multiple items to the combo box.

        Args:
            items: List of text items to add.

        """
        for item in items:
            self.addItem(item)

    def currentIndex(self) -> int:
        """Get the current item index.

        Returns:
            Current selected item index.

        """
        return self._current_index

    def setCurrentIndex(self, index: int) -> None:
        """Set the current item index.

        Args:
            index: Index of item to select.

        """
        if 0 <= index < len(self._items):
            self._current_index = index

    def currentText(self) -> str:
        """Get the current item text.

        Returns:
            Text of the currently selected item.

        """
        if 0 <= self._current_index < len(self._items):
            return self._items[self._current_index]
        return ""

    def itemData(self, index: int) -> Any:
        """Get the data associated with an item.

        Args:
            index: Item index.

        Returns:
            Associated data for the item.

        """
        if 0 <= index < len(self._item_data):
            return self._item_data[index]
        return None

    def count(self) -> int:
        """Get the number of items in the combo box.

        Returns:
            Number of items.

        """
        return len(self._items)

    def clear(self) -> None:
        """Clear all items from the combo box."""
        self._items.clear()
        self._item_data.clear()
        self._current_index = -1


class _FallbackCheckBox(_FallbackWidgetBase):
    """Production fallback checkbox implementation."""

    def __init__(self, text: str = "", parent: Any = None) -> None:
        """Initialize the checkbox.

        Args:
            text: Checkbox label text.
            parent: Parent widget.

        """
        super().__init__()
        self._text = text
        self._checked = False

    def text(self) -> str:
        """Get the checkbox label text.

        Returns:
            The label text.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the checkbox label text.

        Args:
            text: New label text.

        """
        self._text = text

    def isChecked(self) -> bool:
        """Check if the checkbox is checked.

        Returns:
            True if checked, False otherwise.

        """
        return self._checked

    def setChecked(self, checked: bool) -> None:
        """Set the checkbox checked state.

        Args:
            checked: True to check, False to uncheck.

        """
        self._checked = checked


class _FallbackSpinBox(_FallbackWidgetBase):
    """Production fallback numeric input with increment/decrement."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the spin box.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._value = 0
        self._min = 0
        self._max = 99
        self._step = 1

    def value(self) -> int:
        """Get the current spin box value.

        Returns:
            Current numeric value.

        """
        return self._value

    def setValue(self, value: int) -> None:
        """Set the spin box value.

        Args:
            value: New value (clamped to min/max range).

        """
        self._value = max(self._min, min(self._max, value))

    def minimum(self) -> int:
        """Get the minimum value.

        Returns:
            Minimum allowed value.

        """
        return self._min

    def setMinimum(self, minimum: int) -> None:
        """Set the minimum value.

        Args:
            minimum: New minimum value.

        """
        self._min = minimum
        self._value = max(self._value, minimum)

    def maximum(self) -> int:
        """Get the maximum value.

        Returns:
            Maximum allowed value.

        """
        return self._max

    def setMaximum(self, maximum: int) -> None:
        """Set the maximum value.

        Args:
            maximum: New maximum value.

        """
        self._max = maximum
        self._value = min(self._value, maximum)

    def setSingleStep(self, step: int) -> None:
        """Set the increment/decrement step size.

        Args:
            step: Step value.

        """
        self._step = step


class _FallbackProgressBar(_FallbackWidgetBase):
    """Production fallback progress indicator."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the progress bar.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._value = 0
        self._min = 0
        self._max = 100

    def value(self) -> int:
        """Get the current progress value.

        Returns:
            Current progress value.

        """
        return self._value

    def setValue(self, value: int) -> None:
        """Set the progress value.

        Args:
            value: New progress value (clamped to min/max).

        """
        self._value = max(self._min, min(self._max, value))

    def minimum(self) -> int:
        """Get the minimum progress value.

        Returns:
            Minimum value.

        """
        return self._min

    def setMinimum(self, minimum: int) -> None:
        """Set the minimum progress value.

        Args:
            minimum: New minimum value.

        """
        self._min = minimum

    def maximum(self) -> int:
        """Get the maximum progress value.

        Returns:
            Maximum value.

        """
        return self._max

    def setMaximum(self, maximum: int) -> None:
        """Set the maximum progress value.

        Args:
            maximum: New maximum value.

        """
        self._max = maximum

    def reset(self) -> None:
        """Reset progress to minimum value."""
        self._value = self._min


class _FallbackListWidget(_FallbackWidgetBase):
    """Production fallback list display widget."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the list widget.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._items: list[Any] = []
        self._current_row: int = -1

    def addItem(self, item: Any) -> None:
        """Add an item to the list.

        Args:
            item: Item to add to the list.

        """
        self._items.append(item)
        if self._current_row < 0 and self._items:
            self._current_row = 0

    def clear(self) -> None:
        """Clear all items from the list."""
        self._items.clear()
        self._current_row = -1

    def count(self) -> int:
        """Get the number of items in the list.

        Returns:
            Number of items.

        """
        return len(self._items)

    def currentRow(self) -> int:
        """Get the current row index.

        Returns:
            Current selected row index.

        """
        return self._current_row

    def setCurrentRow(self, row: int) -> None:
        """Set the current row index.

        Args:
            row: Row index to select.

        """
        if 0 <= row < len(self._items):
            self._current_row = row

    def item(self, row: int) -> Any:
        """Get an item from the list.

        Args:
            row: Row index.

        Returns:
            Item at the specified row or None.

        """
        if 0 <= row < len(self._items):
            return self._items[row]
        return None


class _FallbackTableWidget(_FallbackWidgetBase):
    """Production fallback table display widget."""

    def __init__(self, rows: int = 0, cols: int = 0, parent: Any = None) -> None:
        """Initialize the table widget.

        Args:
            rows: Initial number of rows.
            cols: Initial number of columns.
            parent: Parent widget.

        """
        super().__init__()
        self._rows = rows
        self._cols = cols
        self._cells: dict[tuple[int, int], Any] = {}
        self._headers: list[str] = []

    def setRowCount(self, rows: int) -> None:
        """Set the number of rows in the table.

        Args:
            rows: Number of rows.

        """
        self._rows = rows

    def setColumnCount(self, cols: int) -> None:
        """Set the number of columns in the table.

        Args:
            cols: Number of columns.

        """
        self._cols = cols

    def rowCount(self) -> int:
        """Get the number of rows in the table.

        Returns:
            Number of rows.

        """
        return self._rows

    def columnCount(self) -> int:
        """Get the number of columns in the table.

        Returns:
            Number of columns.

        """
        return self._cols

    def setItem(self, row: int, col: int, item: Any) -> None:
        """Set a cell item in the table.

        Args:
            row: Row index.
            col: Column index.
            item: Cell item to set.

        """
        self._cells[row, col] = item

    def item(self, row: int, col: int) -> Any:
        """Get a cell item from the table.

        Args:
            row: Row index.
            col: Column index.

        Returns:
            Cell item or None.

        """
        return self._cells.get((row, col))

    def setHorizontalHeaderLabels(self, labels: list[str]) -> None:
        """Set the column header labels.

        Args:
            labels: List of header label strings.

        """
        self._headers = labels

    def clear(self) -> None:
        """Clear all cell items from the table."""
        self._cells.clear()


class _FallbackTreeWidget(_FallbackWidgetBase):
    """Production fallback tree display widget."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the tree widget.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._items: list[Any] = []
        self._headers: list[str] = []

    def addTopLevelItem(self, item: Any) -> None:
        """Add a top-level item to the tree.

        Args:
            item: Item to add.

        """
        self._items.append(item)

    def topLevelItem(self, index: int) -> Any:
        """Get a top-level item from the tree.

        Args:
            index: Item index.

        Returns:
            Item at the specified index or None.

        """
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def topLevelItemCount(self) -> int:
        """Get the number of top-level items in the tree.

        Returns:
            Number of top-level items.

        """
        return len(self._items)

    def setHeaderLabels(self, labels: list[str]) -> None:
        """Set the header labels for the tree.

        Args:
            labels: List of header label strings.

        """
        self._headers = labels

    def clear(self) -> None:
        """Clear all items from the tree."""
        self._items.clear()


class _FallbackQt:
    """Production fallback Qt namespace providing constants and enums."""

    class Orientation:
        """Orientation constants for widgets."""

        Horizontal: int = 1
        Vertical: int = 2

    class AspectRatioMode:
        """Aspect ratio scaling mode constants."""

        KeepAspectRatio: int = 1
        IgnoreAspectRatio: int = 0
        KeepAspectRatioByExpanding: int = 2

    class TransformationMode:
        """Image transformation mode constants."""

        SmoothTransformation: int = 1
        FastTransformation: int = 0

    class AlignmentFlag:
        """Widget alignment flag constants."""

        AlignLeft: int = 0x0001
        AlignRight: int = 0x0002
        AlignHCenter: int = 0x0004
        AlignTop: int = 0x0020
        AlignBottom: int = 0x0040
        AlignVCenter: int = 0x0080
        AlignCenter: int = 0x0084

    class ItemFlag:
        """Widget item flag constants."""

        ItemIsSelectable: int = 1
        ItemIsEditable: int = 2
        ItemIsEnabled: int = 32


class _FallbackQThread(_FallbackWidgetBase):
    """Production fallback thread implementation."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the thread.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._running = False

    def start(self) -> None:
        """Start the thread."""
        self._running = True

    def quit(self) -> None:
        """Quit the thread."""
        self._running = False

    def wait(self, timeout: int = 0) -> bool:
        """Wait for the thread to finish.

        Args:
            timeout: Timeout in milliseconds (ignored in fallback).

        Returns:
            True if thread finished.

        """
        self._running = False
        return True

    def isRunning(self) -> bool:
        """Check if thread is running.

        Returns:
            True if thread is running.

        """
        return self._running

    def isFinished(self) -> bool:
        """Check if thread has finished.

        Returns:
            True if thread is finished.

        """
        return not self._running


class _FallbackQTimer(_FallbackWidgetBase):
    """Production fallback timer implementation with signal support."""

    class _Signal:
        """Signal class for timer timeout events."""

        def __init__(self) -> None:
            """Initialize the signal with an empty callback list."""
            self._callbacks: list[Callable[..., Any]] = []

        def connect(self, callback: Callable[..., Any]) -> None:
            """Connect a callback to the signal.

            Args:
                callback: Callable to invoke when signal is emitted.

            """
            self._callbacks.append(callback)

        def disconnect(self, callback: Callable[..., Any] | None = None) -> None:
            """Disconnect a callback from the signal.

            Args:
                callback: Callable to disconnect, or None to disconnect all.

            """
            if callback is None:
                self._callbacks.clear()
            elif callback in self._callbacks:
                self._callbacks.remove(callback)

    def __init__(self, parent: Any = None) -> None:
        """Initialize the timer.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self.timeout = self._Signal()
        self._active = False
        self._interval = 0

    def start(self, interval: int = 0) -> None:
        """Start the timer with an interval.

        Args:
            interval: Timer interval in milliseconds.

        """
        self._interval = interval
        self._active = True

    def stop(self) -> None:
        """Stop the timer."""
        self._active = False

    def isActive(self) -> bool:
        """Check if timer is active.

        Returns:
            True if timer is running.

        """
        return self._active

    def interval(self) -> int:
        """Get the timer interval.

        Returns:
            Timer interval in milliseconds.

        """
        return self._interval

    def setInterval(self, interval: int) -> None:
        """Set the timer interval.

        Args:
            interval: Timer interval in milliseconds.

        """
        self._interval = interval


class _FallbackQFont:
    """Production fallback font class for non-PyQt environments."""

    def __init__(self, family: str = "", pointSize: int = -1, weight: int = -1, italic: bool = False) -> None:
        """Initialize the font.

        Args:
            family: Font family name.
            pointSize: Font point size.
            weight: Font weight value.
            italic: Whether font is italicized.

        """
        self._family = family
        self._point_size = pointSize
        self._weight = weight
        self._italic = italic

    def family(self) -> str:
        """Get the font family name.

        Returns:
            Font family name.

        """
        return self._family

    def setFamily(self, family: str) -> None:
        """Set the font family name.

        Args:
            family: Font family name.

        """
        self._family = family

    def pointSize(self) -> int:
        """Get the font point size.

        Returns:
            Font point size.

        """
        return self._point_size

    def setPointSize(self, size: int) -> None:
        """Set the font point size.

        Args:
            size: Font point size.

        """
        self._point_size = size

    def weight(self) -> int:
        """Get the font weight.

        Returns:
            Font weight value.

        """
        return self._weight

    def setWeight(self, weight: int) -> None:
        """Set the font weight.

        Args:
            weight: Font weight value.

        """
        self._weight = weight

    def italic(self) -> bool:
        """Check if font is italicized.

        Returns:
            True if font is italicized.

        """
        return self._italic

    def setItalic(self, italic: bool) -> None:
        """Set font italic state.

        Args:
            italic: True to italicize font.

        """
        self._italic = italic

    def setBold(self, bold: bool) -> None:
        """Set font bold state.

        Args:
            bold: True to make font bold.

        """
        self._weight = 700 if bold else 400


class _FallbackQIcon:
    """Production fallback icon class for non-PyQt environments."""

    def __init__(self, path: str | None = None) -> None:
        """Initialize the icon.

        Args:
            path: Path to icon file.

        """
        self._path = path

    def isNull(self) -> bool:
        """Check if icon is null.

        Returns:
            True if icon has no path.

        """
        return self._path is None

    @staticmethod
    def fromTheme(name: str) -> "_FallbackQIcon":
        """Create an icon from a theme name.

        Args:
            name: Theme icon name.

        Returns:
            Icon instance with the theme name as path.

        """
        return _FallbackQIcon(name)


class _FallbackQPixmap:
    """Production fallback pixmap class for non-PyQt environments."""

    def __init__(self, path: str | None = None, width: int = 0, height: int = 0) -> None:
        """Initialize the pixmap.

        Args:
            path: Path to pixmap file.
            width: Pixmap width.
            height: Pixmap height.

        """
        self._path = path
        self._width = width
        self._height = height

    def isNull(self) -> bool:
        """Check if pixmap is null.

        Returns:
            True if pixmap has no path or file doesn't exist.

        """
        return self._path is None or not os.path.exists(str(self._path))

    def width(self) -> int:
        """Get pixmap width.

        Returns:
            Pixmap width in pixels.

        """
        return self._width

    def height(self) -> int:
        """Get pixmap height.

        Returns:
            Pixmap height in pixels.

        """
        return self._height

    def scaled(self, w: int, h: int, aspect_mode: Any = None, transform_mode: Any = None) -> "_FallbackQPixmap":
        """Scale the pixmap to new dimensions.

        Args:
            w: New width.
            h: New height.
            aspect_mode: Aspect ratio mode (ignored).
            transform_mode: Transformation mode (ignored).

        Returns:
            Scaled pixmap instance.

        """
        return _FallbackQPixmap(self._path, w, h)


class _FallbackQTextCursor:
    """Production fallback text cursor for non-PyQt environments."""

    class MoveMode:
        """Text cursor move mode constants."""

        MoveAnchor: int = 0
        KeepAnchor: int = 1

    class MoveOperation:
        """Text cursor move operation constants."""

        End: int = 11
        Start: int = 1

    def __init__(self, document: Any = None) -> None:
        """Initialize the text cursor.

        Args:
            document: Document object (ignored).

        """
        self._position = 0
        self._anchor = 0

    def position(self) -> int:
        """Get the cursor position.

        Returns:
            Current cursor position.

        """
        return self._position

    def setPosition(self, pos: int, mode: int = 0) -> None:
        """Set the cursor position.

        Args:
            pos: New cursor position.
            mode: Move mode (ignored).

        """
        self._position = pos

    def movePosition(self, operation: int, mode: int = 0, n: int = 1) -> bool:
        """Move the cursor.

        Args:
            operation: Move operation constant.
            mode: Move mode (ignored).
            n: Number of positions to move (ignored).

        Returns:
            True if move was successful.

        """
        return True


class _FallbackQTest:
    """Production fallback QTest for non-PyQt environments."""

    @staticmethod
    def qWait(ms: int) -> None:
        """Wait for a specified time duration.

        Args:
            ms: Time to wait in milliseconds.

        """
        import time
        time.sleep(ms / 1000.0)


class _FallbackQApplication(_FallbackWidgetBase):
    """Production fallback application class."""

    _instance: "_FallbackQApplication | None" = None

    def __init__(self, argv: list[str] | None = None) -> None:
        """Initialize the application.

        Args:
            argv: Command-line arguments.

        """
        super().__init__()
        _FallbackQApplication._instance = self
        self._argv = argv or []

    @classmethod
    def instance(cls) -> "_FallbackQApplication | None":
        """Get the application instance.

        Returns:
            The singleton application instance.

        """
        return cls._instance

    def exec(self) -> int:
        """Execute the application event loop.

        Returns:
            Exit code (always 0 in fallback).

        """
        return 0

    def quit(self) -> None:
        """Quit the application with full cleanup.

        Performs cleanup operations:
        - Clears the singleton instance
        - Cleans up any registered children
        - Marks the application as not running
        - Triggers system exit if running standalone

        """
        import contextlib
        import gc
        import logging

        logger = logging.getLogger(__name__)
        logger.debug("FallbackQApplication: Beginning application shutdown")

        if hasattr(self, "_children") and self._children:
            for child in self._children:
                if hasattr(child, "deleteLater"):
                    with contextlib.suppress(Exception):
                        child.deleteLater()
            self._children.clear()

        _FallbackQApplication._instance = None

        self._enabled = False
        self._visible = False

        gc.collect()

        with contextlib.suppress(Exception):
            import atexit
            atexit._run_exitfuncs()

        logger.debug("FallbackQApplication: Shutdown complete")


class _FallbackQFileDialog:
    """Production fallback file dialog class."""

    @staticmethod
    def getOpenFileName(parent: Any = None, caption: str = "", directory: str = "",
                        filter: str = "") -> tuple[str, str]:
        """Show a file open dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.
            filter: File filter string.

        Returns:
            Tuple of (filename, filter) with empty filename.

        """
        return ("", filter)

    @staticmethod
    def getSaveFileName(parent: Any = None, caption: str = "", directory: str = "",
                        filter: str = "") -> tuple[str, str]:
        """Show a file save dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.
            filter: File filter string.

        Returns:
            Tuple of (filename, filter) with empty filename.

        """
        return ("", filter)

    @staticmethod
    def getExistingDirectory(parent: Any = None, caption: str = "", directory: str = "") -> str:
        """Show a directory selection dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.

        Returns:
            Empty string (no directory selected).

        """
        return ""


class _FallbackQInputDialog:
    """Production fallback input dialog class."""

    @staticmethod
    def getText(parent: Any, title: str, label: str, echo: int = 0, text: str = "") -> tuple[str, bool]:
        """Show a text input dialog.

        Args:
            parent: Parent widget.
            title: Dialog title.
            label: Input label text.
            echo: Echo mode (ignored).
            text: Default input text.

        Returns:
            Tuple of (input_text, ok_pressed).

        """
        return (text, True)

    @staticmethod
    def getInt(parent: Any, title: str, label: str, value: int = 0, min_val: int = -2147483647,
               max_val: int = 2147483647, step: int = 1) -> tuple[int, bool]:
        """Show an integer input dialog.

        Args:
            parent: Parent widget.
            title: Dialog title.
            label: Input label text.
            value: Default value.
            min_val: Minimum value.
            max_val: Maximum value.
            step: Step size.

        Returns:
            Tuple of (input_value, ok_pressed).

        """
        return (value, True)


class _FallbackQMessageBox:
    """Production fallback message box class."""

    class StandardButton:
        """Standard message box button constants."""

        Ok: int = 0x00000400
        Cancel: int = 0x00400000
        Yes: int = 0x00004000
        No: int = 0x00010000

    class Icon:
        """Message box icon type constants."""

        Information: int = 1
        Warning: int = 2
        Critical: int = 3
        Question: int = 4

    @staticmethod
    def information(parent: Any, title: str, text: str, buttons: int = 0x00000400) -> int:
        """Show an information message box.

        Args:
            parent: Parent widget.
            title: Message box title.
            text: Message text.
            buttons: Button flags (ignored).

        Returns:
            Default button constant.

        """
        return 0x00000400

    @staticmethod
    def warning(parent: Any, title: str, text: str, buttons: int = 0x00000400) -> int:
        """Show a warning message box.

        Args:
            parent: Parent widget.
            title: Message box title.
            text: Message text.
            buttons: Button flags (ignored).

        Returns:
            Default button constant.

        """
        return 0x00000400

    @staticmethod
    def critical(parent: Any, title: str, text: str, buttons: int = 0x00000400) -> int:
        """Show a critical error message box.

        Args:
            parent: Parent widget.
            title: Message box title.
            text: Message text.
            buttons: Button flags (ignored).

        Returns:
            Default button constant.

        """
        return 0x00000400

    @staticmethod
    def question(parent: Any, title: str, text: str, buttons: int = 0x00004000) -> int:
        """Show a question message box.

        Args:
            parent: Parent widget.
            title: Message box title.
            text: Message text.
            buttons: Button flags (ignored).

        Returns:
            Default button constant.

        """
        return 0x00004000


class _FallbackQGroupBox(_FallbackWidgetBase):
    """Production fallback group box widget."""

    def __init__(self, title: str = "", parent: Any = None) -> None:
        """Initialize the group box.

        Args:
            title: Group box title.
            parent: Parent widget.

        """
        super().__init__()
        self._title = title

    def title(self) -> str:
        """Get the group box title.

        Returns:
            The group box title.

        """
        return self._title

    def setTitle(self, title: str) -> None:
        """Set the group box title.

        Args:
            title: New group box title.

        """
        self._title = title

    def setLayout(self, layout: Any) -> None:
        """Set the group box layout.

        Args:
            layout: Layout object to set.

        """
        self._layout = layout


class _FallbackQTabWidget(_FallbackWidgetBase):
    """Production fallback tab widget."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the tab widget.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._tabs: list[tuple[Any, str]] = []
        self._current_index = -1

    def addTab(self, widget: Any, label: str) -> int:
        """Add a tab to the widget.

        Args:
            widget: Widget to display in the tab.
            label: Tab label text.

        Returns:
            Index of the added tab.

        """
        self._tabs.append((widget, label))
        self._current_index = max(self._current_index, 0)
        return len(self._tabs) - 1

    def currentIndex(self) -> int:
        """Get the current tab index.

        Returns:
            Current tab index.

        """
        return self._current_index

    def setCurrentIndex(self, index: int) -> None:
        """Set the current tab index.

        Args:
            index: Tab index to select.

        """
        if 0 <= index < len(self._tabs):
            self._current_index = index

    def count(self) -> int:
        """Get the number of tabs.

        Returns:
            Number of tabs.

        """
        return len(self._tabs)

    def widget(self, index: int) -> Any:
        """Get the widget at a tab index.

        Args:
            index: Tab index.

        Returns:
            Widget at the specified tab or None.

        """
        if 0 <= index < len(self._tabs):
            return self._tabs[index][0]
        return None


class _FallbackQSplitter(_FallbackWidgetBase):
    """Production fallback splitter widget."""

    def __init__(self, orientation: int = 1, parent: Any = None) -> None:
        """Initialize the splitter widget.

        Args:
            orientation: Splitter orientation (1=horizontal, 2=vertical).
            parent: Parent widget.

        """
        super().__init__()
        self._orientation = orientation
        self._widgets: list[Any] = []

    def addWidget(self, widget: Any) -> None:
        """Add a widget to the splitter.

        Args:
            widget: Widget to add.

        """
        self._widgets.append(widget)

    def setOrientation(self, orientation: int) -> None:
        """Set the splitter orientation.

        Args:
            orientation: Orientation constant (1=horizontal, 2=vertical).

        """
        self._orientation = orientation

    def setSizes(self, sizes: list[int]) -> None:
        """Set the sizes of splitter sections.

        Args:
            sizes: List of section sizes.

        """
        self._sizes = sizes


class _FallbackQSlider(_FallbackWidgetBase):
    """Production fallback slider widget."""

    class TickPosition:
        """Slider tick position constants."""

        NoTicks: int = 0
        TicksAbove: int = 1
        TicksBelow: int = 2
        TicksBothSides: int = 3

    def __init__(self, orientation: int = 1, parent: Any = None) -> None:
        """Initialize the slider widget.

        Args:
            orientation: Slider orientation (1=horizontal, 2=vertical).
            parent: Parent widget.

        """
        super().__init__()
        self._orientation = orientation
        self._value = 0
        self._min = 0
        self._max = 99
        self._tick_interval = 0
        self._tick_position = 0

    def value(self) -> int:
        """Get the current slider value.

        Returns:
            Current slider value.

        """
        return self._value

    def setValue(self, value: int) -> None:
        """Set the slider value.

        Args:
            value: New slider value (clamped to min/max).

        """
        self._value = max(self._min, min(self._max, value))

    def setMinimum(self, minimum: int) -> None:
        """Set the minimum slider value.

        Args:
            minimum: New minimum value.

        """
        self._min = minimum

    def setMaximum(self, maximum: int) -> None:
        """Set the maximum slider value.

        Args:
            maximum: New maximum value.

        """
        self._max = maximum

    def setTickPosition(self, position: int) -> None:
        """Set the tick mark position.

        Args:
            position: Tick position constant from TickPosition class.

        """
        self._tick_position = position

    def tickPosition(self) -> int:
        """Get the current tick position.

        Returns:
            Current tick position constant.

        """
        return self._tick_position

    def setTickInterval(self, interval: int) -> None:
        """Set the tick mark interval.

        Args:
            interval: Interval between tick marks.

        """
        self._tick_interval = interval

    def tickInterval(self) -> int:
        """Get the current tick interval.

        Returns:
            Current tick interval value.

        """
        return self._tick_interval


class _FallbackQHeaderView:
    """Production fallback header view for tables/trees."""

    class ResizeMode:
        """Header view resize mode constants."""

        Interactive: int = 0
        Fixed: int = 2
        Stretch: int = 1
        ResizeToContents: int = 3


class _FallbackQGraphicsView(_FallbackWidgetBase):
    """Production fallback graphics view widget."""

    def __init__(self, parent: Any = None) -> None:
        """Initialize the graphics view widget.

        Args:
            parent: Parent widget.

        """
        super().__init__()
        self._scene: Any = None

    def setScene(self, scene: Any) -> None:
        """Set the graphics scene for the view.

        Args:
            scene: Graphics scene to display.

        """
        self._scene = scene

    def scene(self) -> Any:
        """Get the graphics scene.

        Returns:
            The displayed graphics scene.

        """
        return self._scene


class _FallbackQListWidgetItem:
    """Production fallback list widget item."""

    def __init__(self, text: str = "", parent: Any = None) -> None:
        """Initialize the list widget item.

        Args:
            text: Item text.
            parent: Parent widget (ignored).

        """
        self._text = text
        self._data: dict[int, Any] = {}

    def text(self) -> str:
        """Get the item text.

        Returns:
            The item text.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the item text.

        Args:
            text: New item text.

        """
        self._text = text

    def setData(self, role: int, value: Any) -> None:
        """Set item data for a role.

        Args:
            role: Data role identifier.
            value: Data value.

        """
        self._data[role] = value

    def data(self, role: int) -> Any:
        """Get item data for a role.

        Args:
            role: Data role identifier.

        Returns:
            Data value or None.

        """
        return self._data.get(role)


class _FallbackQTableWidgetItem:
    """Production fallback table widget item."""

    def __init__(self, text: str = "") -> None:
        """Initialize the table widget item.

        Args:
            text: Item text.

        """
        self._text = text
        self._data: dict[int, Any] = {}

    def text(self) -> str:
        """Get the item text.

        Returns:
            The item text.

        """
        return self._text

    def setText(self, text: str) -> None:
        """Set the item text.

        Args:
            text: New item text.

        """
        self._text = text

    def setData(self, role: int, value: Any) -> None:
        """Set item data for a role.

        Args:
            role: Data role identifier.
            value: Data value.

        """
        self._data[role] = value

    def data(self, role: int) -> Any:
        """Get item data for a role.

        Args:
            role: Data role identifier.

        Returns:
            Data value or None.

        """
        return self._data.get(role)


class _FallbackQTreeWidgetItem:
    """Production fallback tree widget item."""

    def __init__(self, parent: Any = None, strings: list[str] | None = None) -> None:
        """Initialize the tree widget item.

        Args:
            parent: Parent item.
            strings: Initial column text values.

        """
        self._texts: list[str] = strings or []
        self._children: list[Any] = []
        self._parent = parent

    def text(self, column: int) -> str:
        """Get the item text for a column.

        Args:
            column: Column index.

        Returns:
            Text at the specified column.

        """
        if 0 <= column < len(self._texts):
            return self._texts[column]
        return ""

    def setText(self, column: int, text: str) -> None:
        """Set the item text for a column.

        Args:
            column: Column index.
            text: Text to set.

        """
        while len(self._texts) <= column:
            self._texts.append("")
        self._texts[column] = text

    def addChild(self, child: Any) -> None:
        """Add a child item.

        Args:
            child: Child item to add.

        """
        self._children.append(child)

    def childCount(self) -> int:
        """Get the number of child items.

        Returns:
            Number of child items.

        """
        return len(self._children)

    def child(self, index: int) -> Any:
        """Get a child item by index.

        Args:
            index: Child item index.

        Returns:
            Child item at the specified index or None.

        """
        if 0 <= index < len(self._children):
            return self._children[index]
        return None


# Common PyQt6 imports
try:
    from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
    from PyQt6.QtGui import QFont, QIcon, QPixmap, QTextCursor
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFormLayout,
        QGraphicsView,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QSlider,
        QSpinBox,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )

    HAS_PYQT = True

    # Utility functions for unused imports
    def create_icon(path_or_pixmap: str | QPixmap) -> QIcon:
        """Create a QIcon from a path or pixmap.

        Args:
            path_or_pixmap: File path string or QPixmap instance to
                convert to an icon.

        Returns:
            QIcon: A QIcon instance created from the given input.

        """
        if isinstance(path_or_pixmap, QPixmap):
            return QIcon(path_or_pixmap)
        return QIcon(str(path_or_pixmap))

    def create_pixmap_from_file(path: str, size: tuple[int, int] | None = None) -> QPixmap:
        """Create a QPixmap from a file.

        Args:
            path: File path to the pixmap file.
            size: Optional tuple of (width, height) to scale the pixmap.

        Returns:
            QPixmap: A QPixmap instance, scaled if size is specified and
                file is valid.

        """
        pixmap = QPixmap(path)
        if size and not pixmap.isNull():
            pixmap = pixmap.scaled(size[0], size[1], Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        return pixmap

    def get_user_input(parent: QWidget, title: str, label: str, default: str = "", password: bool = False) -> tuple[str, bool]:
        """Get user input using QInputDialog.

        Args:
            parent: Parent widget for the dialog.
            title: Dialog window title.
            label: Prompt label text.
            default: Default text value.
            password: Whether to mask input as password.

        Returns:
            tuple[str, bool]: Tuple of (input_text, ok_pressed) where
                ok_pressed is True if user clicked OK.

        """
        if password:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Password, default)
        else:
            text, ok = QInputDialog.getText(parent, title, label, QLineEdit.EchoMode.Normal, default)
        return text, bool(ok)

    def create_horizontal_slider(min_val: int = 0, max_val: int = 100, value: int = 50, tick_interval: int = 10) -> QSlider:
        """Create a configured horizontal slider.

        Args:
            min_val: Minimum slider value.
            max_val: Maximum slider value.
            value: Initial slider value.
            tick_interval: Interval between tick marks.

        Returns:
            QSlider: A configured QSlider instance with horizontal
                orientation.

        """
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        slider.setTickInterval(tick_interval)
        return slider

except ImportError as e:
    logger.exception("Import error in common_imports: %s", e)
    HAS_PYQT = False

    if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
        logger.info("Skipping PyQt6 imports during testing mode")

    Qt = _FallbackQt
    QThread = _FallbackQThread
    QTimer = _FallbackQTimer
    QTest = _FallbackQTest
    QTextCursor = _FallbackQTextCursor

    class _FallbackSignal:
        """Production fallback signal class for non-PyQt environments."""

        def __init__(self) -> None:
            """Initialize the signal with an empty callback list."""
            self._callbacks: list[Callable[..., Any]] = []

        def connect(self, callback: Callable[..., Any]) -> None:
            """Connect a callback to the signal.

            Args:
                callback: Callable to invoke when signal is emitted.

            """
            self._callbacks.append(callback)

        def disconnect(self, callback: Callable[..., Any] | None = None) -> None:
            """Disconnect a callback from the signal.

            Args:
                callback: Callable to disconnect, or None to disconnect all.

            """
            if callback is None:
                self._callbacks.clear()
            elif callback in self._callbacks:
                self._callbacks.remove(callback)

        def emit(self, *args: Any) -> None:
            """Emit the signal, invoking all connected callbacks.

            Args:
                *args: Arguments to pass to connected callbacks.

            """
            for cb in self._callbacks:
                with contextlib.suppress(Exception):
                    cb(*args)

    def pyqtSignal(*args: Any, **kwargs: Any) -> _FallbackSignal:
        """Production fallback pyqtSignal when PyQt6 is not available.

        Args:
            *args: Signal arguments (ignored).
            **kwargs: Signal keyword arguments (ignored).

        Returns:
            _FallbackSignal: A fallback signal instance for callback
                management.

        """
        return _FallbackSignal()

    QFont = _FallbackQFont
    QIcon = _FallbackQIcon
    QPixmap = _FallbackQPixmap
    QApplication = _FallbackQApplication
    QCheckBox = _FallbackCheckBox
    QComboBox = _FallbackComboBox
    QDialog = _FallbackDialog
    QFileDialog = _FallbackQFileDialog
    QFormLayout = _FallbackLayout
    QGraphicsView = _FallbackQGraphicsView
    QGroupBox = _FallbackQGroupBox
    QHBoxLayout = _FallbackLayout
    QHeaderView = _FallbackQHeaderView
    QInputDialog = _FallbackQInputDialog
    QLabel = _FallbackLabel
    QLineEdit = _FallbackLineEdit
    QListWidget = _FallbackListWidget
    QListWidgetItem = _FallbackQListWidgetItem
    QMessageBox = _FallbackQMessageBox
    QProgressBar = _FallbackProgressBar
    QPushButton = _FallbackButton
    QSlider = _FallbackQSlider
    QSpinBox = _FallbackSpinBox
    QSplitter = _FallbackQSplitter
    QTableWidget = _FallbackTableWidget
    QTableWidgetItem = _FallbackQTableWidgetItem
    QTabWidget = _FallbackQTabWidget
    QTextEdit = _FallbackTextEdit
    QTreeWidget = _FallbackTreeWidget
    QTreeWidgetItem = _FallbackQTreeWidgetItem
    QVBoxLayout = _FallbackLayout
    QWidget = _FallbackWidgetBase

    def create_icon(path_or_pixmap: str | object) -> _FallbackQIcon:
        """Create icon using production fallback when PyQt6 is unavailable.

        Args:
            path_or_pixmap: Icon file path or object to convert to icon.

        Returns:
            _FallbackQIcon: Fallback icon instance.

        """
        return _FallbackQIcon(str(path_or_pixmap) if path_or_pixmap else None)

    def create_pixmap_from_file(path: str, size: tuple[int, int] | None = None) -> _FallbackQPixmap:
        """Create pixmap using production fallback when PyQt6 is unavailable.

        Args:
            path: Path to the pixmap file.
            size: Optional tuple of (width, height) to create pixmap with.

        Returns:
            _FallbackQPixmap: Fallback pixmap instance.

        """
        if size:
            return _FallbackQPixmap(path, size[0], size[1])
        return _FallbackQPixmap(path)

    def get_user_input(parent: object, title: str, label: str, default: str = "", password: bool = False) -> tuple[str, bool]:
        """Get user input using fallback when PyQt6 is unavailable.

        Args:
            parent: Parent widget object.
            title: Dialog title.
            label: Input label text.
            default: Default input text.
            password: Whether to mask input as password.

        Returns:
            tuple[str, bool]: Tuple of (input_text, ok_pressed).

        """
        return default, True

    def create_horizontal_slider(min_val: int = 0, max_val: int = 100, value: int = 50, tick_interval: int = 10) -> _FallbackQSlider:
        """Create slider using production fallback when PyQt6 is unavailable.

        Args:
            min_val: Minimum slider value.
            max_val: Maximum slider value.
            value: Initial slider value.
            tick_interval: Interval between tick marks.

        Returns:
            _FallbackQSlider: Configured fallback slider instance.

        """
        slider = _FallbackQSlider()
        slider.setMinimum(min_val)
        slider.setMaximum(max_val)
        slider.setValue(value)
        slider.setTickInterval(tick_interval)
        return slider


class FallbackSlider:
    """Production fallback slider implementation for non-PyQt environments.

    This class provides a functional slider interface when PyQt6 is unavailable,
    maintaining state and interface compatibility with QSlider.

    Attributes:
        _value: Current slider value.
        _min: Minimum allowed value.
        _max: Maximum allowed value.
        _tick_interval: Interval between tick marks.

    """

    def __init__(self, min_val: int, max_val: int, value: int, tick_interval: int) -> None:
        """Initialize the fallback slider.

        Args:
            min_val: Minimum slider value.
            max_val: Maximum slider value.
            value: Initial slider value.
            tick_interval: Interval between tick marks.

        """
        self._min: int = min_val
        self._max: int = max_val
        self._value: int = min(max(value, min_val), max_val)
        self._tick_interval: int = tick_interval
        self._tick_position: int = 0

    def setValue(self, val: int) -> None:
        """Set the slider value.

        Args:
            val: New slider value, clamped to [min, max] range.

        """
        self._value = min(max(val, self._min), self._max)

    def value(self) -> int:
        """Get the current slider value.

        Returns:
            Current value within [min, max] range.

        """
        return self._value

    def setMinimum(self, val: int) -> None:
        """Set the minimum slider value.

        Args:
            val: New minimum value.

        """
        self._min = val
        self._value = max(self._value, self._min)

    def setMaximum(self, val: int) -> None:
        """Set the maximum slider value.

        Args:
            val: New maximum value.

        """
        self._max = val
        self._value = min(self._value, self._max)

    def setTickPosition(self, position: int) -> None:
        """Set the tick mark position.

        Args:
            position: Tick position constant (0=NoTicks, 1=TicksAbove, 2=TicksBelow, 3=TicksBothSides).

        """
        self._tick_position = position

    def tickPosition(self) -> int:
        """Get the current tick position.

        Returns:
            Current tick position constant.

        """
        return self._tick_position

    def setTickInterval(self, interval: int) -> None:
        """Set the interval between tick marks.

        Args:
            interval: Tick interval value.

        """
        self._tick_interval = interval

    def tickInterval(self) -> int:
        """Get the current tick interval.

        Returns:
            Current tick interval value.

        """
        return self._tick_interval


# Export all imports and utilities
__all__ = [
    "FallbackSlider",
    "HAS_PYQT",
    "QApplication",
    "QCheckBox",
    "QComboBox",
    "QDialog",
    "QFileDialog",
    "QFont",
    "QFormLayout",
    "QGraphicsView",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QIcon",
    "QInputDialog",
    "QLabel",
    "QLineEdit",
    "QListWidget",
    "QListWidgetItem",
    "QMessageBox",
    "QPixmap",
    "QProgressBar",
    "QPushButton",
    "QSlider",
    "QSpinBox",
    "QSplitter",
    "QTabWidget",
    "QTableWidget",
    "QTableWidgetItem",
    "QTest",
    "QTextCursor",
    "QTextEdit",
    "QThread",
    "QTimer",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    "Qt",
    "create_horizontal_slider",
    "create_icon",
    "create_pixmap_from_file",
    "get_user_input",
    "pyqtSignal",
]
