"""
Common UI button utilities to avoid code duplication.
"""

try:
    from PyQt5.QtWidgets import QPushButton
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


def add_extra_buttons(header_layout, extra_buttons, widget_refs=None):
    """
    Add extra buttons to a header layout with consistent styling.
    
    Args:
        header_layout: Qt layout to add buttons to
        extra_buttons: List of (button_text, callback) tuples
        widget_refs: Optional dict to store button references
        
    Returns:
        dict: Dictionary of button text -> button widget
    """
    if not PYQT_AVAILABLE or not extra_buttons:
        return {}

    buttons = {}

    for button_text, callback in extra_buttons:
        btn = QPushButton(button_text)
        btn.clicked.connect(callback)

        # Apply special styling for Analyze Binary button
        if button_text == "Analyze Binary":
            btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")

        header_layout.addWidget(btn)
        buttons[button_text] = btn

        # Store reference if widget_refs provided
        if widget_refs is not None:
            if button_text == "Analyze Binary":
                widget_refs['analyze_btn'] = btn
            elif 'extra_buttons' in widget_refs:
                widget_refs['extra_buttons'][button_text] = btn

    return buttons


def get_button_style(button_text):
    """
    Get the appropriate style for a button based on its text.
    
    Args:
        button_text: Text of the button
        
    Returns:
        str: Style sheet string
    """
    if button_text == "Analyze Binary":
        return "QPushButton { background-color: #2196F3; color: white; font-weight: bold; }"
    return ""
