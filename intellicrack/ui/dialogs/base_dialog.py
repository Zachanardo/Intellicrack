"""
Base Dialog Module

Provides common functionality for dialog components to eliminate code duplication.
"""

from typing import List, Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class BaseTemplateDialog(QDialog):
    """
    Base class for dialogs with template selection functionality.
    """

    template_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.template_list = None
        self.template_combo = None

    def create_template_widget(self, title: str, templates: List[str],
                             use_combo: bool = False,
                             category_names: Optional[List[str]] = None) -> QWidget:
        """
        Create a standard template selection widget.
        
        Args:
            title: Title for the template group box
            templates: List of template names
            use_combo: Use QComboBox instead of QListWidget
            category_names: Optional category names for combo box
            
        Returns:
            QWidget containing the template selection UI
        """
        widget = QWidget()
        layout = QVBoxLayout()

        # Template group
        template_group = QGroupBox(title)
        template_layout = QVBoxLayout()

        # Category selection if provided
        if category_names and use_combo:
            category_layout = QHBoxLayout()
            category_layout.addWidget(QLabel("Category:"))

            category_combo = QComboBox()
            category_combo.addItems(category_names)
            category_layout.addWidget(category_combo)
            category_layout.addStretch()

            template_layout.addLayout(category_layout)

        # Template selection
        if use_combo:
            self.template_combo = QComboBox()
            self.template_combo.addItems(templates)
            self.template_combo.currentTextChanged.connect(self._on_template_selected)
            template_layout.addWidget(self.template_combo)
        else:
            self.template_list = QListWidget()
            self.template_list.addItems(templates)
            self.template_list.itemSelectionChanged.connect(self._on_template_list_selected)
            template_layout.addWidget(self.template_list)

        # Action buttons
        button_layout = QHBoxLayout()

        load_btn = QPushButton("Load Template")
        load_btn.clicked.connect(self.load_template)
        button_layout.addWidget(load_btn)

        save_btn = QPushButton("Save as Template")
        save_btn.clicked.connect(self.save_template)
        button_layout.addWidget(save_btn)

        button_layout.addStretch()
        template_layout.addLayout(button_layout)

        template_group.setLayout(template_layout)
        layout.addWidget(template_group)

        # Template details
        details_group = QGroupBox("Template Details")
        details_layout = QVBoxLayout()

        self.template_details = QTextEdit()
        self.template_details.setReadOnly(True)
        self.template_details.setMaximumHeight(150)

        details_layout.addWidget(self.template_details)
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        layout.addStretch()
        widget.setLayout(layout)

        return widget

    def _on_template_selected(self, template_name: str):
        """Handle combo box template selection."""
        self.template_selected.emit(template_name)
        self.on_template_selected(template_name)

    def _on_template_list_selected(self):
        """Handle list widget template selection."""
        if self.template_list and self.template_list.currentItem():
            template_name = self.template_list.currentItem().text()
            self.template_selected.emit(template_name)
            self.on_template_selected(template_name)

    def on_template_selected(self, template_name: str):
        """Override this method to handle template selection."""
        pass

    def load_template(self):
        """Override this method to implement template loading."""
        pass

    def save_template(self):
        """Override this method to implement template saving."""
        pass

    @staticmethod
    def finalize_widget(widget: QWidget, layout: QVBoxLayout) -> QWidget:
        """
        Common widget finalization pattern.
        
        Args:
            widget: Widget to finalize
            layout: Layout to apply to the widget
            
        Returns:
            The finalized widget
        """
        layout.addStretch()
        widget.setLayout(layout)
        return widget
