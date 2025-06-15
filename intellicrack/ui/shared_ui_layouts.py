"""
Shared UI Layout Utilities

Common UI layout patterns to eliminate code duplication between dialog classes.
"""

from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QFormLayout, QPushButton, 
                            QLineEdit, QTabWidget, QGroupBox, QWidget)
from typing import List, Tuple, Optional, Callable


class UILayoutHelpers:
    """
    Shared UI layout helper functions for consistent dialog creation.
    """

    @staticmethod
    def create_tabbed_dialog_layout(dialog, window_title: str, size: Tuple[int, int] = (1000, 700),
                                   is_modal: bool = False) -> Tuple[QVBoxLayout, QTabWidget]:
        """
        Create a standard tabbed dialog layout structure.
        
        Args:
            dialog: The dialog widget to configure
            window_title: Title for the dialog window
            size: (width, height) tuple for dialog size
            is_modal: Whether dialog should be modal
            
        Returns:
            Tuple of (main_layout, tab_widget)
        """
        dialog.setWindowTitle(window_title)
        dialog.setMinimumSize(size[0], size[1])
        
        if is_modal:
            dialog.setModal(True)
        
        # Create main layout
        main_layout = QVBoxLayout()
        
        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        return main_layout, tab_widget

    @staticmethod
    def create_dialog_buttons(button_specs: List[Tuple[str, Callable, bool]], 
                             layout: QVBoxLayout) -> List[QPushButton]:
        """
        Create standard dialog buttons with consistent layout.
        
        Args:
            button_specs: List of (text, callback, is_right_aligned) tuples
            layout: Main layout to add buttons to
            
        Returns:
            List of created QPushButton objects
        """
        button_layout = QHBoxLayout()
        buttons = []
        
        # Add left-aligned buttons first
        for text, callback, is_right_aligned in button_specs:
            if not is_right_aligned:
                btn = QPushButton(text)
                btn.clicked.connect(callback)
                button_layout.addWidget(btn)
                buttons.append(btn)
        
        # Add stretch to push right-aligned buttons to the right
        button_layout.addStretch()
        
        # Add right-aligned buttons
        for text, callback, is_right_aligned in button_specs:
            if is_right_aligned:
                btn = QPushButton(text)
                btn.clicked.connect(callback)
                button_layout.addWidget(btn)
                buttons.append(btn)
        
        layout.addLayout(button_layout)
        return buttons

    @staticmethod
    def create_file_browse_widget(placeholder_text: str = "", 
                                 browse_callback: Optional[Callable] = None,
                                 browse_text: str = "Browse...") -> Tuple[QHBoxLayout, QLineEdit, QPushButton]:
        """
        Create a file browse widget with line edit and browse button.
        
        Args:
            placeholder_text: Placeholder text for the line edit
            browse_callback: Callback function for browse button click
            browse_text: Text for the browse button
            
        Returns:
            Tuple of (layout, line_edit, browse_button)
        """
        layout = QHBoxLayout()
        
        line_edit = QLineEdit()
        if placeholder_text:
            line_edit.setPlaceholderText(placeholder_text)
        
        browse_btn = QPushButton(browse_text)
        if browse_callback:
            browse_btn.clicked.connect(browse_callback)
        
        layout.addWidget(line_edit)
        layout.addWidget(browse_btn)
        
        return layout, line_edit, browse_btn

    @staticmethod
    def create_config_group(title: str, use_form_layout: bool = True) -> Tuple[QGroupBox, QVBoxLayout]:
        """
        Create a configuration group box with appropriate layout.
        
        Args:
            title: Title for the group box
            use_form_layout: Whether to use QFormLayout (True) or QVBoxLayout (False)
            
        Returns:
            Tuple of (group_box, layout)
        """
        group = QGroupBox(title)
        
        if use_form_layout:
            layout = QFormLayout()
        else:
            layout = QVBoxLayout()
        
        group.setLayout(layout)
        return group, layout

    @staticmethod
    def finalize_widget_layout(widget: QWidget, layout) -> QWidget:
        """
        Common widget finalization pattern - adds stretch and sets layout.
        
        Args:
            widget: Widget to finalize
            layout: Layout to add stretch to and set on widget
            
        Returns:
            The widget (for method chaining)
        """
        if hasattr(layout, 'addStretch'):
            layout.addStretch()
        widget.setLayout(layout)
        return widget

    @staticmethod
    def setup_standard_form_field(layout, label_text: str, widget: QWidget) -> None:
        """
        Add a standard form field to a form layout.
        
        Args:
            layout: QFormLayout to add to
            label_text: Text for the label
            widget: Widget to add as the field
        """
        if hasattr(layout, 'addRow'):
            layout.addRow(label_text, widget)
        else:
            # Fallback for non-form layouts
            if hasattr(layout, 'addWidget'):
                layout.addWidget(widget)

    @staticmethod
    def create_tabs_from_specs(tab_widget: QTabWidget, 
                              tab_specs: List[Tuple[str, QWidget]]) -> None:
        """
        Add multiple tabs to a tab widget from specifications.
        
        Args:
            tab_widget: QTabWidget to add tabs to
            tab_specs: List of (tab_title, tab_widget) tuples
        """
        for title, widget in tab_specs:
            tab_widget.addTab(widget, title)


# Export main class
__all__ = ['UILayoutHelpers']