"""Window sizing utilities for responsive UI design"""

from PyQt6.QtWidgets import QApplication


def get_default_window_size(
    width_percentage=0.8, height_percentage=0.8, min_width=800, min_height=600
):
    """Calculate appropriate window size based on screen dimensions

    Args:
        width_percentage: Percentage of screen width to use (0.0-1.0)
        height_percentage: Percentage of screen height to use (0.0-1.0)
        min_width: Minimum window width
        min_height: Minimum window height

    Returns:
        tuple: (width, height)

    """
    if QApplication.instance():
        screen = QApplication.primaryScreen()
        if screen:
            screen_rect = screen.availableGeometry()
            width = max(int(screen_rect.width() * width_percentage), min_width)
            height = max(int(screen_rect.height() * height_percentage), min_height)
            return width, height
    return min_width, min_height


def center_window_on_screen(window):
    """Center a window on the primary screen

    Args:
        window: QWidget to center

    """
    if QApplication.instance():
        screen = QApplication.primaryScreen()
        if screen:
            screen_rect = screen.availableGeometry()
            window_rect = window.frameGeometry()
            center_x = (screen_rect.width() - window_rect.width()) // 2
            center_y = (screen_rect.height() - window_rect.height()) // 2
            window.move(screen_rect.x() + center_x, screen_rect.y() + center_y)


def get_dialog_size(dialog_type="standard"):
    """Get appropriate dialog size based on type

    Args:
        dialog_type: Type of dialog ("small", "standard", "large", "full")

    Returns:
        tuple: (width, height, min_width, min_height)

    """
    screen_width, screen_height = get_default_window_size(1.0, 1.0, 1024, 768)

    dialog_configs = {
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

    width = max(int(screen_width * config["width_pct"]), config["min_width"])
    height = max(int(screen_height * config["height_pct"]), config["min_height"])

    return width, height, config["min_width"], config["min_height"]


def apply_dialog_sizing(dialog, dialog_type="standard"):
    """Apply dynamic sizing to a dialog based on screen size

    Args:
        dialog: QDialog instance
        dialog_type: Type of dialog ("small", "standard", "large", "full")

    """
    width, height, min_width, min_height = get_dialog_size(dialog_type)
    dialog.setMinimumSize(min_width, min_height)
    dialog.resize(width, height)
    center_window_on_screen(dialog)
