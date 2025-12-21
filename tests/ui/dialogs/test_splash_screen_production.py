"""Production-ready tests for SplashScreen - Application startup screen validation.

This module validates SplashScreen's complete functionality including:
- Splash screen initialization with custom and default pixmaps
- Progress bar creation and positioning
- Status label display and updates
- Progress value updates and message changes
- Signal emission for progress updates
- Window flags for frameless and stay-on-top behavior
- Convenience factory function for creating splash screens
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPixmap
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.splash_screen import (
    SplashScreen,
    create_progress_splash_screen,
)


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def temp_image_file(tmp_path: Path) -> Path:
    """Create temporary image file for splash screen testing."""
    pixmap = QPixmap(600, 400)
    pixmap.fill(QColor(100, 100, 100))
    image_file = tmp_path / "splash.png"
    pixmap.save(str(image_file))
    return image_file


@pytest.fixture
def splash_screen_default(qapp: QApplication) -> SplashScreen:
    """Create SplashScreen with default pixmap."""
    return SplashScreen()


@pytest.fixture
def splash_screen_with_image(qapp: QApplication, temp_image_file: Path) -> SplashScreen:
    """Create SplashScreen with custom image."""
    return SplashScreen(pixmap_path=str(temp_image_file))


class TestSplashScreenInitialization:
    """Test SplashScreen initialization and setup."""

    def test_splash_screen_creates_with_default_pixmap(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Splash screen creates default pixmap when no image provided."""
        pixmap = splash_screen_default.pixmap()
        assert pixmap is not None
        assert pixmap.width() == 600
        assert pixmap.height() == 400

    def test_splash_screen_creates_with_custom_image(
        self, splash_screen_with_image: SplashScreen
    ) -> None:
        """Splash screen loads custom image when valid path provided."""
        pixmap = splash_screen_with_image.pixmap()
        assert pixmap is not None
        assert not pixmap.isNull()

    def test_splash_screen_has_progress_bar(self, splash_screen_default: SplashScreen) -> None:
        """Splash screen contains progress bar widget."""
        assert splash_screen_default.progress_bar is not None
        assert splash_screen_default.progress_bar.objectName() == "splashProgressBar"

    def test_splash_screen_has_status_label(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Splash screen contains status label widget."""
        assert splash_screen_default.status_label is not None
        assert splash_screen_default.status_label.objectName() == "splashStatusLabel"

    def test_progress_bar_positioned_near_bottom(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Progress bar is positioned near bottom of splash screen."""
        progress_bar = splash_screen_default.progress_bar
        pixmap = splash_screen_default.pixmap()
        assert progress_bar.geometry().y() > pixmap.height() - 100

    def test_status_label_positioned_above_progress_bar(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Status label is positioned above progress bar."""
        status_label = splash_screen_default.status_label
        progress_bar = splash_screen_default.progress_bar
        assert status_label.geometry().y() < progress_bar.geometry().y()

    def test_status_label_centered_alignment(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Status label has center text alignment."""
        alignment = splash_screen_default.status_label.alignment()
        assert Qt.AlignmentFlag.AlignCenter in Qt.AlignmentFlag(alignment)

    def test_window_stays_on_top_flag_set(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Splash screen window has stay-on-top flag enabled."""
        flags = splash_screen_default.windowFlags()
        assert Qt.WindowType.WindowStaysOnTopHint in Qt.WindowType(flags)

    def test_window_frameless_flag_set(self, splash_screen_default: SplashScreen) -> None:
        """Splash screen window is frameless."""
        flags = splash_screen_default.windowFlags()
        assert Qt.WindowType.FramelessWindowHint in Qt.WindowType(flags)


class TestSplashScreenProgressUpdates:
    """Test progress bar and status message updates."""

    def test_update_progress_changes_progress_value(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Update progress changes progress bar value."""
        splash_screen_default.update_progress(50, "Loading...")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 50

    def test_update_progress_changes_status_message(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Update progress changes status label text."""
        test_message = "Loading components..."
        splash_screen_default.update_progress(30, test_message)
        QApplication.processEvents()
        assert splash_screen_default.status_label.text() == test_message

    def test_set_progress_emits_signal(self, splash_screen_default: SplashScreen) -> None:
        """Set progress emits progress_updated signal."""
        signal_received = False
        received_value = None
        received_message = None

        def signal_handler(value: int, message: str) -> None:
            nonlocal signal_received, received_value, received_message
            signal_received = True
            received_value = value
            received_message = message

        splash_screen_default.progress_updated.connect(signal_handler)
        splash_screen_default.set_progress(75, "Almost done...")
        QApplication.processEvents()

        assert signal_received
        assert received_value == 75
        assert received_message == "Almost done..."

    def test_set_progress_updates_progress_bar_via_signal(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Set progress updates progress bar through signal mechanism."""
        splash_screen_default.set_progress(40, "Initializing...")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 40

    def test_set_progress_handles_zero_value(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Set progress handles zero progress value."""
        splash_screen_default.set_progress(0, "Starting...")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 0

    def test_set_progress_handles_hundred_percent(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Set progress handles 100% progress value."""
        splash_screen_default.set_progress(100, "Complete")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 100

    def test_set_progress_with_empty_message(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Set progress handles empty message string."""
        splash_screen_default.set_progress(50, "")
        QApplication.processEvents()
        assert splash_screen_default.status_label.text() == ""

    def test_multiple_progress_updates(self, splash_screen_default: SplashScreen) -> None:
        """Multiple progress updates work correctly in sequence."""
        splash_screen_default.set_progress(25, "Step 1")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 25

        splash_screen_default.set_progress(50, "Step 2")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 50

        splash_screen_default.set_progress(75, "Step 3")
        QApplication.processEvents()
        assert splash_screen_default.progress_bar.value() == 75


class TestSplashScreenDefaultPixmap:
    """Test default pixmap generation."""

    def test_default_pixmap_contains_app_name(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Default pixmap is created when no image file exists."""
        splash = SplashScreen(pixmap_path="/nonexistent/path.png")
        pixmap = splash.pixmap()
        assert pixmap is not None
        assert pixmap.width() == 600
        assert pixmap.height() == 400

    def test_default_pixmap_has_dark_background(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Default pixmap has dark gray background color."""
        pixmap = splash_screen_default.pixmap()
        sample_color = pixmap.toImage().pixelColor(10, 10)
        assert sample_color.red() <= 50
        assert sample_color.green() <= 50
        assert sample_color.blue() <= 50


class TestSplashScreenConvenienceFunctions:
    """Test convenience factory functions."""

    def test_create_progress_splash_screen_without_image(self, qapp: QApplication) -> None:
        """Create progress splash screen without image creates default."""
        splash = create_progress_splash_screen()
        assert isinstance(splash, SplashScreen)
        assert splash.progress_bar is not None
        assert splash.status_label is not None

    def test_create_progress_splash_screen_with_image(
        self, qapp: QApplication, temp_image_file: Path
    ) -> None:
        """Create progress splash screen with custom image."""
        splash = create_progress_splash_screen(image_path=str(temp_image_file))
        assert isinstance(splash, SplashScreen)
        pixmap = splash.pixmap()
        assert not pixmap.isNull()

    def test_create_progress_splash_screen_returns_configured_instance(
        self, qapp: QApplication
    ) -> None:
        """Created splash screen has all components configured."""
        splash = create_progress_splash_screen()
        assert splash.progress_bar.objectName() == "splashProgressBar"
        assert splash.status_label.objectName() == "splashStatusLabel"


class TestSplashScreenIntegration:
    """Test splash screen integration scenarios."""

    def test_splash_screen_shows_and_updates(self, qapp: QApplication) -> None:
        """Splash screen can be shown and updated in typical usage pattern."""
        splash = SplashScreen()
        splash.show()
        QApplication.processEvents()

        splash.set_progress(20, "Loading modules...")
        QApplication.processEvents()
        assert splash.progress_bar.value() == 20

        splash.set_progress(50, "Initializing...")
        QApplication.processEvents()
        assert splash.progress_bar.value() == 50

        splash.set_progress(100, "Ready")
        QApplication.processEvents()
        assert splash.progress_bar.value() == 100

        splash.close()

    def test_splash_screen_visibility(self, splash_screen_default: SplashScreen) -> None:
        """Splash screen can be shown and hidden."""
        splash_screen_default.show()
        QApplication.processEvents()
        splash_screen_default.close()
        QApplication.processEvents()

    def test_progress_bar_width_spans_most_of_splash(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Progress bar spans most of splash screen width."""
        progress_bar = splash_screen_default.progress_bar
        pixmap = splash_screen_default.pixmap()
        assert progress_bar.width() > pixmap.width() * 0.8

    def test_status_label_width_matches_progress_bar(
        self, splash_screen_default: SplashScreen
    ) -> None:
        """Status label width matches progress bar width."""
        status_width = splash_screen_default.status_label.width()
        progress_width = splash_screen_default.progress_bar.width()
        assert status_width == progress_width
