"""
Base utilities for common dialog patterns.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from PyQt6.QtWidgets import QHBoxLayout, QProgressBar, QPushButton


def create_standard_control_layout(buttons_config, include_progress=True):
    """
    Create a standard control layout with buttons and optional progress bar.

    Args:
        buttons_config: List of tuples (text, enabled, callback) for buttons
        include_progress: Whether to include a progress bar

    Returns:
        tuple: (layout, buttons_dict, progress_bar)
    """
    control_layout = QHBoxLayout()
    buttons = {}

    # Create buttons
    for button_text, enabled, callback in buttons_config:
        btn = QPushButton(button_text)
        btn.setEnabled(enabled)
        if callback:
            btn.clicked.connect(callback)
        control_layout.addWidget(btn)

        # Store button reference by extracting key name
        key = (
            button_text.lower()
            .replace(" ", "_")
            .replace("▶️", "run")
            .replace("⏹️", "stop")
            .replace("💾", "save")
            .replace("🔧", "generate")
            .strip()
        )
        buttons[key] = btn

    # Add stretch
    control_layout.addStretch()

    # Add progress bar if requested
    progress_bar = None
    if include_progress:
        progress_bar = QProgressBar()
        progress_bar.setVisible(False)
        control_layout.addWidget(progress_bar)

    return control_layout, buttons, progress_bar
