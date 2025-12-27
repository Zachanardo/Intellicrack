"""Protocol definitions for UI abstractions.

This module defines Protocols for UI components that abstract over PyQt5/PyQt6
and headless fallback implementations. These protocols enable type-safe UI code
that works across different GUI frameworks.

Note: Method names like setEnabled, isVisible, etc. follow Qt naming conventions
intentionally to maintain API compatibility with PyQt. The noqa: N802 comments
suppress the lowercase function name warnings for these cases.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


if TYPE_CHECKING:
    from collections.abc import Callable


class StandardButton(IntEnum):
    """Standard button types for message boxes."""

    NoButton = 0x00000000
    Ok = 0x00000400
    Save = 0x00000800
    SaveAll = 0x00001000
    Open = 0x00002000
    Yes = 0x00004000
    YesToAll = 0x00008000
    No = 0x00010000
    NoToAll = 0x00020000
    Abort = 0x00040000
    Retry = 0x00080000
    Ignore = 0x00100000
    Close = 0x00200000
    Cancel = 0x00400000
    Discard = 0x00800000
    Help = 0x01000000
    Apply = 0x02000000
    Reset = 0x04000000
    RestoreDefaults = 0x08000000


class MessageBoxIcon(IntEnum):
    """Message box icon types."""

    NoIcon = 0
    Information = 1
    Warning = 2
    Critical = 3
    Question = 4


@runtime_checkable
class WidgetProtocol(Protocol):
    """Protocol defining the interface for widget-like objects.

    This protocol enables type-safe code that works with both PyQt widgets
    and headless fallback implementations.
    """

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802, FBT001
        """Enable or disable the widget.

        Args:
            enabled: Whether the widget should be enabled.

        """
        ...

    def isEnabled(self) -> bool:  # noqa: N802
        """Check if the widget is enabled.

        Returns:
            True if the widget is enabled, False otherwise.

        """
        ...

    def setVisible(self, visible: bool) -> None:  # noqa: N802, FBT001
        """Show or hide the widget.

        Args:
            visible: Whether the widget should be visible.

        """
        ...

    def isVisible(self) -> bool:  # noqa: N802
        """Check if the widget is visible.

        Returns:
            True if the widget is visible, False otherwise.

        """
        ...

    def show(self) -> None:
        """Show the widget."""
        ...

    def hide(self) -> None:
        """Hide the widget."""
        ...

    def close(self) -> bool:
        """Close the widget.

        Returns:
            True if the widget was closed, False otherwise.

        """
        ...

    def setLayout(self, layout: object) -> None:  # noqa: N802
        """Set the widget's layout.

        Args:
            layout: The layout to set (typically a QLayout or LayoutProtocol).

        """
        ...


@runtime_checkable
class MessageBoxProtocol(Protocol):
    """Protocol for message box dialogs.

    This protocol defines the interface for showing message boxes that
    works with both PyQt and headless implementations.
    """

    @staticmethod
    def information(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show an information message box.

        Args:
            parent: Parent widget (can be None).
            title: Message box title.
            text: Message text.
            buttons: Buttons to show (OR'd StandardButton values).
            default_button: Default button.

        Returns:
            The button that was clicked (StandardButton value).

        """
        ...

    @staticmethod
    def warning(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a warning message box.

        Args:
            parent: Parent widget (can be None).
            title: Message box title.
            text: Message text.
            buttons: Buttons to show.
            default_button: Default button.

        Returns:
            The button that was clicked.

        """
        ...

    @staticmethod
    def critical(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a critical error message box.

        Args:
            parent: Parent widget (can be None).
            title: Message box title.
            text: Message text.
            buttons: Buttons to show.
            default_button: Default button.

        Returns:
            The button that was clicked.

        """
        ...

    @staticmethod
    def question(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Yes | StandardButton.No,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a question message box.

        Args:
            parent: Parent widget (can be None).
            title: Message box title.
            text: Question text.
            buttons: Buttons to show.
            default_button: Default button.

        Returns:
            The button that was clicked.

        """
        ...


@runtime_checkable
class FileDialogProtocol(Protocol):
    """Protocol for file dialogs."""

    @staticmethod
    def getOpenFileName(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
        file_filter: str = "",
    ) -> tuple[str, str]:
        """Show an open file dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.
            file_filter: File filter string.

        Returns:
            Tuple of (selected_file, selected_filter).

        """
        ...

    @staticmethod
    def getSaveFileName(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
        file_filter: str = "",
    ) -> tuple[str, str]:
        """Show a save file dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.
            file_filter: File filter string.

        Returns:
            Tuple of (selected_file, selected_filter).

        """
        ...

    @staticmethod
    def getExistingDirectory(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
    ) -> str:
        """Show a directory selection dialog.

        Args:
            parent: Parent widget.
            caption: Dialog caption.
            directory: Initial directory.

        Returns:
            Selected directory path or empty string.

        """
        ...


@runtime_checkable
class SignalProtocol(Protocol):
    """Protocol for Qt-like signals."""

    def emit(self, *args: object) -> None:
        """Emit the signal with given arguments.

        Args:
            *args: Arguments to pass to connected slots.

        """
        ...

    def connect(self, slot: Callable[..., object]) -> None:
        """Connect a slot to this signal.

        Args:
            slot: The callable to connect.

        """
        ...

    def disconnect(self, slot: Callable[..., object] | None = None) -> None:
        """Disconnect a slot from this signal.

        Args:
            slot: The callable to disconnect (or None to disconnect all).

        """
        ...


@runtime_checkable
class LineEditProtocol(Protocol):
    """Protocol for line edit widgets."""

    def text(self) -> str:
        """Get the current text.

        Returns:
            The current text content.

        """
        ...

    def setText(self, text: str) -> None:  # noqa: N802
        """Set the text content.

        Args:
            text: The text to set.

        """
        ...

    def setReadOnly(self, read_only: bool) -> None:  # noqa: N802, FBT001
        """Set read-only state.

        Args:
            read_only: Whether the widget should be read-only.

        """
        ...

    def isReadOnly(self) -> bool:  # noqa: N802
        """Check if read-only.

        Returns:
            True if read-only, False otherwise.

        """
        ...


@runtime_checkable
class PushButtonProtocol(Protocol):
    """Protocol for push button widgets."""

    def text(self) -> str:
        """Get the button text.

        Returns:
            The button text.

        """
        ...

    def setText(self, text: str) -> None:  # noqa: N802
        """Set the button text.

        Args:
            text: The text to set.

        """
        ...

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802, FBT001
        """Enable or disable the button.

        Args:
            enabled: Whether the button should be enabled.

        """
        ...

    def click(self) -> None:
        """Programmatically click the button."""
        ...


@runtime_checkable
class GroupBoxProtocol(Protocol):
    """Protocol for group box widgets."""

    def title(self) -> str:
        """Get the group box title.

        Returns:
            The title string.

        """
        ...

    def setTitle(self, title: str) -> None:  # noqa: N802
        """Set the group box title.

        Args:
            title: The title to set.

        """
        ...


@runtime_checkable
class LayoutProtocol(Protocol):
    """Protocol for layout objects.

    Note: The addWidget signature uses `object` rather than `WidgetProtocol`
    to maintain compatibility with Qt's QLayout.addWidget signature which
    accepts QWidget | None with optional stretch and alignment parameters.
    Using `object` allows both Qt widgets and Protocol-conforming widgets.
    """

    def addWidget(  # noqa: N802
        self,
        widget: object,
        stretch: int = ...,
        alignment: int = ...,
    ) -> None:
        """Add a widget to the layout.

        Args:
            widget: The widget to add (typically a QWidget or WidgetProtocol).
            stretch: Optional stretch factor.
            alignment: Optional alignment flags.

        """
        ...


class DialogResult(BaseModel):
    """Result from a dialog interaction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    accepted: bool = Field(description="Whether the dialog was accepted")
    button_clicked: int = Field(default=StandardButton.NoButton, description="The button that was clicked")
    data: str = Field(default="", description="Any data returned by the dialog")


class FileDialogResult(BaseModel):
    """Result from a file dialog."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(default="", description="Selected file/directory path")
    filter_used: str = Field(default="", description="The filter that was selected")
    cancelled: bool = Field(default=False, description="Whether the dialog was cancelled")


class BinarySelectionWidgets(BaseModel):
    """References to widgets in a binary selection header.

    This model replaces the dict[str, Any] return type of
    create_binary_selection_header().
    """

    model_config = ConfigDict(frozen=False, extra="allow", arbitrary_types_allowed=True)

    group: object = Field(default=None, description="The QGroupBox widget")
    path_edit: object = Field(default=None, description="The QLineEdit widget")
    browse_btn: object = Field(default=None, description="The browse QPushButton widget")
    extra_buttons: dict[str, object] = Field(default_factory=dict, description="Extra buttons mapped by name")


class HeadlessWidget:
    """Headless fallback widget implementation.

    This class provides a no-op implementation of WidgetProtocol for
    headless (non-GUI) environments.
    """

    _enabled: bool
    _visible: bool

    def __init__(self) -> None:
        """Initialize the headless widget."""
        self._enabled = True
        self._visible = True

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802, FBT001
        """Enable or disable the widget.

        Args:
            enabled: Whether the widget should be enabled.

        """
        self._enabled = enabled

    def isEnabled(self) -> bool:  # noqa: N802
        """Check if the widget is enabled.

        Returns:
            True if the widget is enabled, False otherwise.

        """
        return self._enabled

    def setVisible(self, visible: bool) -> None:  # noqa: N802, FBT001
        """Show or hide the widget.

        Args:
            visible: Whether the widget should be visible.

        """
        self._visible = visible

    def isVisible(self) -> bool:  # noqa: N802
        """Check if the widget is visible.

        Returns:
            True if the widget is visible, False otherwise.

        """
        return self._visible

    def show(self) -> None:
        """Show the widget."""
        self._visible = True

    def hide(self) -> None:
        """Hide the widget."""
        self._visible = False

    def close(self) -> bool:
        """Close the widget.

        Returns:
            True always for headless widgets.

        """
        self._visible = False
        return True

    def setLayout(self, layout: object) -> None:  # noqa: N802
        """Set the widget's layout (no-op for headless).

        Args:
            layout: The layout to set (ignored in headless mode).

        """


class HeadlessMessageBox:
    """Headless fallback message box implementation.

    This class logs messages instead of showing dialogs for headless environments.
    """

    @staticmethod
    def information(
        parent: WidgetProtocol | None,  # noqa: ARG004
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,  # noqa: ARG004
        default_button: int = StandardButton.NoButton,  # noqa: ARG004
    ) -> int:
        """Log an information message.

        Args:
            parent: Parent widget (ignored in headless mode).
            title: Message title.
            text: Message text.
            buttons: Buttons (ignored in headless mode).
            default_button: Default button (ignored in headless mode).

        Returns:
            StandardButton.Ok always.

        """
        import logging

        logging.getLogger(__name__).info("[%s] %s", title, text)
        return StandardButton.Ok

    @staticmethod
    def warning(
        parent: WidgetProtocol | None,  # noqa: ARG004
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,  # noqa: ARG004
        default_button: int = StandardButton.NoButton,  # noqa: ARG004
    ) -> int:
        """Log a warning message.

        Args:
            parent: Parent widget (ignored in headless mode).
            title: Message title.
            text: Message text.
            buttons: Buttons (ignored in headless mode).
            default_button: Default button (ignored in headless mode).

        Returns:
            StandardButton.Ok always.

        """
        import logging

        logging.getLogger(__name__).warning("[%s] %s", title, text)
        return StandardButton.Ok

    @staticmethod
    def critical(
        parent: WidgetProtocol | None,  # noqa: ARG004
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,  # noqa: ARG004
        default_button: int = StandardButton.NoButton,  # noqa: ARG004
    ) -> int:
        """Log a critical error message.

        Args:
            parent: Parent widget (ignored in headless mode).
            title: Message title.
            text: Message text.
            buttons: Buttons (ignored in headless mode).
            default_button: Default button (ignored in headless mode).

        Returns:
            StandardButton.Ok always.

        """
        import logging

        logging.getLogger(__name__).critical("[%s] %s", title, text)
        return StandardButton.Ok

    @staticmethod
    def question(
        parent: WidgetProtocol | None,  # noqa: ARG004
        title: str,
        text: str,
        buttons: int = StandardButton.Yes | StandardButton.No,  # noqa: ARG004
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Log a question and return default answer.

        Args:
            parent: Parent widget (ignored in headless mode).
            title: Question title.
            text: Question text.
            buttons: Buttons (ignored in headless mode).
            default_button: Default button to return.

        Returns:
            The default button if set, otherwise StandardButton.Yes.

        """
        import logging

        logging.getLogger(__name__).info("[Question: %s] %s", title, text)
        if default_button != StandardButton.NoButton:
            return default_button
        return StandardButton.Yes


class HeadlessFileDialog:
    """Headless fallback file dialog implementation.

    Returns empty values for headless environments.
    """

    @staticmethod
    def getOpenFileName(  # noqa: N802
        parent: WidgetProtocol | None,  # noqa: ARG004
        caption: str = "",  # noqa: ARG004
        directory: str = "",  # noqa: ARG004
        file_filter: str = "",  # noqa: ARG004
    ) -> tuple[str, str]:
        """Return empty result for headless mode.

        Args:
            parent: Parent widget (ignored).
            caption: Dialog caption (ignored).
            directory: Initial directory (ignored).
            file_filter: File filter (ignored).

        Returns:
            Empty tuple ("", "").

        """
        return ("", "")

    @staticmethod
    def getSaveFileName(  # noqa: N802
        parent: WidgetProtocol | None,  # noqa: ARG004
        caption: str = "",  # noqa: ARG004
        directory: str = "",  # noqa: ARG004
        file_filter: str = "",  # noqa: ARG004
    ) -> tuple[str, str]:
        """Return empty result for headless mode.

        Args:
            parent: Parent widget (ignored).
            caption: Dialog caption (ignored).
            directory: Initial directory (ignored).
            file_filter: File filter (ignored).

        Returns:
            Empty tuple ("", "").

        """
        return ("", "")

    @staticmethod
    def getExistingDirectory(  # noqa: N802
        parent: WidgetProtocol | None,  # noqa: ARG004
        caption: str = "",  # noqa: ARG004
        directory: str = "",  # noqa: ARG004
    ) -> str:
        """Return empty result for headless mode.

        Args:
            parent: Parent widget (ignored).
            caption: Dialog caption (ignored).
            directory: Initial directory (ignored).

        Returns:
            Empty string.

        """
        return ""


class QtMessageBoxAdapter:
    """Adapter that wraps PyQt6 QMessageBox with Protocol-compatible interface.

    This adapter uses ctypes to pass the parent widget pointer directly to Qt,
    bypassing Python's type system entirely at the C level.
    """

    @staticmethod
    def _get_qt_parent(parent: WidgetProtocol | None) -> object:
        """Convert Protocol parent to Qt-compatible parent.

        At runtime, if parent is a QWidget, it's returned directly.
        If parent is None or a HeadlessWidget, None is returned.
        """
        if parent is None:
            return None
        if isinstance(parent, HeadlessWidget):
            return None
        return parent

    @staticmethod
    def information(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show an information message box using Qt."""
        try:
            from PyQt6.QtWidgets import QMessageBox, QWidget

            qt_parent = QtMessageBoxAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessMessageBox.information(parent, title, text, buttons, default_button)

            qt_buttons = QMessageBox.StandardButton(buttons)
            result = QMessageBox.information(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                title,
                text,
                qt_buttons,
            )
            return int(result)
        except ImportError:
            return HeadlessMessageBox.information(parent, title, text, buttons, default_button)

    @staticmethod
    def warning(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a warning message box using Qt."""
        try:
            from PyQt6.QtWidgets import QMessageBox, QWidget

            qt_parent = QtMessageBoxAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessMessageBox.warning(parent, title, text, buttons, default_button)

            qt_buttons = QMessageBox.StandardButton(buttons)
            result = QMessageBox.warning(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                title,
                text,
                qt_buttons,
            )
            return int(result)
        except ImportError:
            return HeadlessMessageBox.warning(parent, title, text, buttons, default_button)

    @staticmethod
    def critical(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a critical message box using Qt."""
        try:
            from PyQt6.QtWidgets import QMessageBox, QWidget

            qt_parent = QtMessageBoxAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessMessageBox.critical(parent, title, text, buttons, default_button)

            qt_buttons = QMessageBox.StandardButton(buttons)
            result = QMessageBox.critical(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                title,
                text,
                qt_buttons,
            )
            return int(result)
        except ImportError:
            return HeadlessMessageBox.critical(parent, title, text, buttons, default_button)

    @staticmethod
    def question(
        parent: WidgetProtocol | None,
        title: str,
        text: str,
        buttons: int = StandardButton.Yes | StandardButton.No,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        """Show a question message box using Qt."""
        try:
            from PyQt6.QtWidgets import QMessageBox, QWidget

            qt_parent = QtMessageBoxAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessMessageBox.question(parent, title, text, buttons, default_button)

            qt_buttons = QMessageBox.StandardButton(buttons)
            result = QMessageBox.question(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                title,
                text,
                qt_buttons,
            )
            return int(result)
        except ImportError:
            return HeadlessMessageBox.question(parent, title, text, buttons, default_button)


class QtFileDialogAdapter:
    """Adapter that wraps PyQt6 QFileDialog with Protocol-compatible interface."""

    @staticmethod
    def _get_qt_parent(parent: WidgetProtocol | None) -> object:
        """Convert Protocol parent to Qt-compatible parent."""
        if parent is None:
            return None
        if isinstance(parent, HeadlessWidget):
            return None
        return parent

    @staticmethod
    def getOpenFileName(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
        file_filter: str = "",
    ) -> tuple[str, str]:
        """Show an open file dialog using Qt."""
        try:
            from PyQt6.QtWidgets import QFileDialog, QWidget

            qt_parent = QtFileDialogAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessFileDialog.getOpenFileName(parent, caption, directory, file_filter)

            result = QFileDialog.getOpenFileName(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                caption,
                directory,
                file_filter,
            )
            return result
        except ImportError:
            return HeadlessFileDialog.getOpenFileName(parent, caption, directory, file_filter)

    @staticmethod
    def getSaveFileName(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
        file_filter: str = "",
    ) -> tuple[str, str]:
        """Show a save file dialog using Qt."""
        try:
            from PyQt6.QtWidgets import QFileDialog, QWidget

            qt_parent = QtFileDialogAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessFileDialog.getSaveFileName(parent, caption, directory, file_filter)

            result = QFileDialog.getSaveFileName(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                caption,
                directory,
                file_filter,
            )
            return result
        except ImportError:
            return HeadlessFileDialog.getSaveFileName(parent, caption, directory, file_filter)

    @staticmethod
    def getExistingDirectory(  # noqa: N802
        parent: WidgetProtocol | None,
        caption: str = "",
        directory: str = "",
    ) -> str:
        """Show a directory selection dialog using Qt."""
        try:
            from PyQt6.QtWidgets import QFileDialog, QWidget

            qt_parent = QtFileDialogAdapter._get_qt_parent(parent)
            if qt_parent is not None and not isinstance(qt_parent, QWidget):
                return HeadlessFileDialog.getExistingDirectory(parent, caption, directory)

            result = QFileDialog.getExistingDirectory(
                qt_parent if isinstance(qt_parent, QWidget) else None,
                caption,
                directory,
            )
            return result
        except ImportError:
            return HeadlessFileDialog.getExistingDirectory(parent, caption, directory)


def get_message_box() -> type[HeadlessMessageBox] | type[QtMessageBoxAdapter]:
    """Get the appropriate MessageBox implementation.

    Returns:
        QtMessageBoxAdapter if PyQt6 is available, HeadlessMessageBox otherwise.

    """
    try:
        from PyQt6.QtWidgets import QMessageBox  # noqa: F401

        return QtMessageBoxAdapter
    except ImportError:
        return HeadlessMessageBox


def get_file_dialog() -> type[HeadlessFileDialog] | type[QtFileDialogAdapter]:
    """Get the appropriate FileDialog implementation.

    Returns:
        QtFileDialogAdapter if PyQt6 is available, HeadlessFileDialog otherwise.

    """
    try:
        from PyQt6.QtWidgets import QFileDialog  # noqa: F401

        return QtFileDialogAdapter
    except ImportError:
        return HeadlessFileDialog
