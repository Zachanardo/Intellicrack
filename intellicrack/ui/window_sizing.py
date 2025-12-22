"""Window sizing utilities for responsive UI design.

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

from typing import Any

from intellicrack.handlers.pyqt6_handler import QApplication


def get_default_window_size(
    width_percentage: float = 0.8,
    height_percentage: float = 0.8,
    min_width: int = 800,
    min_height: int = 600,
) -> tuple[int, int]:
    """Calculate appropriate window size based on screen dimensions.

    Args:
        width_percentage: Percentage of screen width to use (0.0-1.0).
        height_percentage: Percentage of screen height to use (0.0-1.0).
        min_width: Minimum window width in pixels.
        min_height: Minimum window height in pixels.

    Returns:
        Tuple of (width, height) representing the calculated window dimensions.

    """
    if QApplication.instance():
        if screen := QApplication.primaryScreen():
            screen_rect = screen.availableGeometry()
            width = max(int(screen_rect.width() * width_percentage), min_width)
            height = max(int(screen_rect.height() * height_percentage), min_height)
            return width, height
    return min_width, min_height


def center_window_on_screen(window: Any) -> None:
    """Center a window on the primary screen.

    Args:
        window: QWidget instance to center on the primary screen.

    """
    if QApplication.instance():
        if screen := QApplication.primaryScreen():
            screen_rect = screen.availableGeometry()
            window_rect = window.frameGeometry()
            center_x = (screen_rect.width() - window_rect.width()) // 2
            center_y = (screen_rect.height() - window_rect.height()) // 2
            window.move(screen_rect.x() + center_x, screen_rect.y() + center_y)


def get_dialog_size(dialog_type: str = "standard") -> tuple[int, int, int, int]:
    """Get appropriate dialog size based on type.

    Args:
        dialog_type: Type of dialog. Valid values are "small", "standard",
            "large", or "full". Defaults to "standard".

    Returns:
        Tuple of (width, height, min_width, min_height) dimensions in pixels
        for the specified dialog type.

    """
    screen_width, screen_height = get_default_window_size(1.0, 1.0, 1024, 768)

    dialog_configs: dict[str, dict[str, float | int]] = {
        "small": {
            "width_pct": 0.4,
            "height_pct": 0.3,
            "min_width": 400,
            "min_height": 200,
        },
        "standard": {
            "width_pct": 0.6,
            "height_pct": 0.5,
            "min_width": 600,
            "min_height": 400,
        },
        "large": {
            "width_pct": 0.8,
            "height_pct": 0.7,
            "min_width": 800,
            "min_height": 600,
        },
        "full": {
            "width_pct": 0.9,
            "height_pct": 0.85,
            "min_width": 1000,
            "min_height": 700,
        },
    }

    config = dialog_configs.get(dialog_type, dialog_configs["standard"])

    width = max(int(screen_width * float(config["width_pct"])), int(config["min_width"]))
    height = max(int(screen_height * float(config["height_pct"])), int(config["min_height"]))

    return width, height, int(config["min_width"]), int(config["min_height"])


def apply_dialog_sizing(dialog: Any, dialog_type: str = "standard") -> None:
    """Apply dynamic sizing to a dialog based on screen size.

    Args:
        dialog: QDialog instance to resize and center on screen.
        dialog_type: Type of dialog. Valid values are "small", "standard",
            "large", or "full". Defaults to "standard".

    """
    width, height, min_width, min_height = get_dialog_size(dialog_type)
    dialog.setMinimumSize(min_width, min_height)
    dialog.resize(width, height)
    center_window_on_screen(dialog)
