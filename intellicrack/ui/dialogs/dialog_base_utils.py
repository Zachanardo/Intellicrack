"""Base utilities for common dialog patterns.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from collections.abc import Callable

from intellicrack.handlers.pyqt6_handler import QHBoxLayout, QProgressBar, QPushButton


def create_standard_control_layout(
    buttons_config: list[tuple[str, bool, Callable[[bool], None] | None]],
    include_progress: bool = True,
) -> tuple[QHBoxLayout, dict[str, QPushButton], QProgressBar | None]:
    """Create a standard control layout with buttons and optional progress bar.

    Args:
        buttons_config: List of tuples containing (button_text, enabled_state, callback_function).
            Each tuple specifies a button's text, initial enabled state, and optional click callback.
        include_progress: Whether to include a progress bar in the layout. Defaults to True.

    Returns:
        A tuple containing the control layout, a dictionary mapping button keys to QPushButton objects,
        and an optional QProgressBar (None if include_progress is False).

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
            .replace("", "save")
            .replace("", "generate")
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
