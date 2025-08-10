"""Splash screen dialog for Intellicrack application.

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

import logging
import os

from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QColor,
    QFont,
    QLabel,
    QPainter,
    QPixmap,
    QProgressBar,
    QSplashScreen,
    Qt,
    pyqtSignal,
)

logger = logging.getLogger(__name__)


class SplashScreen(QSplashScreen):
    """Custom splash screen with progress bar for Intellicrack.

    Shows loading progress during application initialization.
    """

    progress_updated = pyqtSignal(int, str)

    def __init__(self, pixmap_path: str | None = None):
        """Initialize the splash screen.

        Args:
            pixmap_path: Path to splash image (optional)

        """
        # Create default pixmap if none provided
        if pixmap_path and os.path.exists(pixmap_path):
            pixmap = QPixmap(pixmap_path)
        else:
            # Create a default splash screen
            pixmap = QPixmap(600, 400)
            pixmap.fill(QColor(45, 45, 45))

            # Draw some text
            painter = QPainter(pixmap)
            painter.setPen(Qt.GlobalColor.white)
            font = QFont("Arial", 24, QFont.Bold)
            painter.setFont(font)
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "Intellicrack")

            font.setPointSize(12)
            font.setBold(False)
            painter.setFont(font)
            painter.drawText(
                pixmap.rect().adjusted(0, 50, 0, 0),
                Qt.AlignmentFlag.AlignCenter,
                "Advanced Binary Analysis Suite",
            )
            painter.end()

        super().__init__(pixmap)

        # Setup progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(50, pixmap.height() - 50, pixmap.width() - 100, 20)
        from ..style_utils import get_splash_progress_bar_style

        self.progress_bar.setStyleSheet(get_splash_progress_bar_style())

        # Status label
        self.status_label = QLabel(self)
        self.status_label.setGeometry(50, pixmap.height() - 80, pixmap.width() - 100, 20)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: white; background-color: transparent;")

        # Connect signal
        self.progress_updated.connect(self.update_progress)

        # Set window flags
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)

    def update_progress(self, value: int, message: str):
        """Update progress bar and status message."""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        QApplication.processEvents()

    def set_progress(self, value: int, message: str = ""):
        """Set progress value and optional message."""
        self.progress_updated.emit(value, message)


def create_progress_splash_screen(image_path: str | None = None) -> SplashScreen:
    """Create and return a progress splash screen.

    Args:
        image_path: Optional path to splash image

    Returns:
        SplashScreen instance

    """
    return SplashScreen(image_path)


# For compatibility
IntellicrackApp = SplashScreen


__all__ = ["IntellicrackApp", "SplashScreen", "create_progress_splash_screen"]
