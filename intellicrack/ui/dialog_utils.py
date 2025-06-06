"""Common dialog utilities and methods."""

from .common_imports import *


def setup_footer(dialog, layout):
    """Setup standard dialog footer with status and close button."""
    footer_layout = QHBoxLayout()
    
    dialog.status_label = QLabel("Ready")
    dialog.status_label.setStyleSheet("QLabel { color: #666; }")
    
    dialog.close_btn = QPushButton("Close")
    dialog.close_btn.clicked.connect(dialog.close)
    
    footer_layout.addWidget(dialog.status_label)
    footer_layout.addStretch()
    footer_layout.addWidget(dialog.close_btn)
    
    layout.addLayout(footer_layout)


def setup_binary_header(dialog, layout):
    """Setup header with binary selection."""
    header_group = QGroupBox("Target Binary")
    header_layout = QHBoxLayout(header_group)
    
    dialog.binary_path_edit = QLineEdit(getattr(dialog, 'binary_path', ''))
    dialog.binary_path_edit.setPlaceholderText("Select target binary file...")
    
    dialog.browse_btn = QPushButton("Browse")
    dialog.browse_btn.clicked.connect(dialog.browse_binary)
    
    header_layout.addWidget(dialog.binary_path_edit)
    header_layout.addWidget(dialog.browse_btn)
    
    layout.addWidget(header_group)


def connect_binary_signals(dialog):
    """Connect common binary-related signals."""
    dialog.binary_path_edit.textChanged.connect(dialog.on_binary_path_changed)


def browse_binary_file(dialog):
    """Standard binary file browser."""
    file_path, _ = QFileDialog.getOpenFileName(
        dialog, "Select Target Binary", "",
        "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
    )
    if file_path:
        dialog.binary_path_edit.setText(file_path)
        dialog.binary_path = file_path


def on_binary_path_changed(dialog, text):
    """Handle binary path change."""
    dialog.binary_path = text