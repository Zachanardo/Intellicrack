"""
Widget Factory for Common UI Patterns

This module provides utility functions for creating common widget patterns
to reduce code duplication across dialog implementations.
"""

from typing import Any, Callable, Dict, List, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)


def create_tree_widget(
    headers: List[str], item_changed_callback: Optional[Callable] = None
) -> QTreeWidget:
    """
    Create a QTreeWidget with standard configuration.

    Args:
        headers: List of header labels
        item_changed_callback: Optional callback for item changes

    Returns:
        Configured QTreeWidget
    """
    tree = QTreeWidget()
    tree.setHeaderLabels(headers)
    if item_changed_callback:
        tree.itemChanged.connect(item_changed_callback)
    return tree


def create_console_text_edit(font_size: int = 9, read_only: bool = True) -> QTextEdit:
    """
    Create a console-style QTextEdit widget.

    Args:
        font_size: Font size for the text
        read_only: Whether the text edit should be read-only

    Returns:
        Configured QTextEdit
    """
    console = QTextEdit()
    console.setReadOnly(read_only)
    console.setFont(QFont("Consolas", font_size))
    return console


def create_input_field(
    placeholder_text: Optional[str] = None, default_value: Optional[str] = None
) -> QLineEdit:
    """
    Create a QLineEdit input field with optional placeholder and default value.

    Args:
        placeholder_text: Optional placeholder text
        default_value: Optional default value

    Returns:
        Configured QLineEdit
    """
    line_edit = QLineEdit()
    if placeholder_text:
        line_edit.setPlaceholderText(placeholder_text)
    if default_value:
        line_edit.setText(default_value)
    return line_edit


def create_button_layout(
    button_configs: List[Dict[str, Any]], add_stretch: bool = True
) -> QHBoxLayout:
    """
    Create a horizontal layout with buttons.

    Args:
        button_configs: List of button configuration dictionaries
                       Each dict should have 'text' and 'callback' keys
                       Optional 'icon' key for button icons
        add_stretch: Whether to add stretch at the end

    Returns:
        QHBoxLayout with buttons
    """
    layout = QHBoxLayout()

    for config in button_configs:
        button = QPushButton(config["text"])
        button.clicked.connect(config["callback"])
        if "icon" in config:
            button.setIcon(config["icon"])
        layout.addWidget(button)

    if add_stretch:
        layout.addStretch()

    return layout


def create_list_widget(
    item_clicked_callback: Optional[Callable] = None,
    context_menu_callback: Optional[Callable] = None,
) -> QListWidget:
    """
    Create a QListWidget with optional callbacks.

    Args:
        item_clicked_callback: Optional callback for item clicks
        context_menu_callback: Optional callback for context menu

    Returns:
        Configured QListWidget
    """
    list_widget = QListWidget()

    if item_clicked_callback:
        list_widget.itemClicked.connect(item_clicked_callback)

    if context_menu_callback:
        list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        list_widget.customContextMenuRequested.connect(context_menu_callback)

    return list_widget


def create_grouped_widget(title: str, content_widget: QWidget) -> QGroupBox:
    """
    Create a QGroupBox containing the specified widget.

    Args:
        title: Title for the group box
        content_widget: Widget to place inside the group box

    Returns:
        QGroupBox containing the content widget
    """
    group_box = QGroupBox(title)
    layout = QVBoxLayout()
    layout.addWidget(content_widget)
    group_box.setLayout(layout)
    return group_box


def create_standard_dialog_buttons(buttons: List[str], callbacks: List[Callable]) -> QHBoxLayout:
    """
    Create standard dialog buttons (OK, Cancel, Apply, etc.).

    Args:
        buttons: List of button texts
        callbacks: List of corresponding callback functions

    Returns:
        QHBoxLayout with standard dialog buttons
    """
    if len(buttons) != len(callbacks):
        raise ValueError("Number of buttons must match number of callbacks")

    layout = QHBoxLayout()
    layout.addStretch()

    for button_text, callback in zip(buttons, callbacks):
        button = QPushButton(button_text)
        button.clicked.connect(callback)
        layout.addWidget(button)

    return layout


__all__ = [
    "create_tree_widget",
    "create_console_text_edit",
    "create_input_field",
    "create_button_layout",
    "create_list_widget",
    "create_grouped_widget",
    "create_standard_dialog_buttons",
]
