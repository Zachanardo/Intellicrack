"""Production tests for window sizing utilities.

This module tests the window sizing and positioning functions that
provide responsive UI design based on screen dimensions.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

from typing import Any

import pytest

from intellicrack.ui.window_sizing import (
    apply_dialog_sizing,
    center_window_on_screen,
    get_default_window_size,
    get_dialog_size,
)

QApplication: Any = None
QDialog: Any = None
QWidget: Any = None
HAS_QT = False

try:
    from intellicrack.handlers.pyqt6_handler import (
        PYQT6_AVAILABLE,
        QApplication,
        QDialog,
        QWidget,
    )

    HAS_QT = PYQT6_AVAILABLE
except ImportError:
    pass


class FakeScreen:
    """Real screen simulator for testing screen geometry calculations."""

    def __init__(self, width: int, height: int, x: int = 0, y: int = 0) -> None:
        """Initialize fake screen with specified dimensions.

        Args:
            width: Screen width in pixels.
            height: Screen height in pixels.
            x: Screen X offset.
            y: Screen Y offset.
        """
        self._width = width
        self._height = height
        self._x = x
        self._y = y

    def availableGeometry(self) -> "FakeGeometry":
        """Get available screen geometry.

        Returns:
            FakeGeometry instance with screen dimensions.
        """
        return FakeGeometry(self._width, self._height, self._x, self._y)


class FakeGeometry:
    """Real geometry object for testing dimension calculations."""

    def __init__(self, width: int, height: int, x: int = 0, y: int = 0) -> None:
        """Initialize geometry with specified dimensions.

        Args:
            width: Geometry width in pixels.
            height: Geometry height in pixels.
            x: Geometry X offset.
            y: Geometry Y offset.
        """
        self._width = width
        self._height = height
        self._x = x
        self._y = y

    def width(self) -> int:
        """Get width.

        Returns:
            Width in pixels.
        """
        return self._width

    def height(self) -> int:
        """Get height.

        Returns:
            Height in pixels.
        """
        return self._height

    def x(self) -> int:
        """Get X offset.

        Returns:
            X offset in pixels.
        """
        return self._x

    def y(self) -> int:
        """Get Y offset.

        Returns:
            Y offset in pixels.
        """
        return self._y


class FakeQApplication:
    """Real QApplication simulator for testing without Qt dependency."""

    _instance: "FakeQApplication | None" = None
    _screen: FakeScreen | None = None

    def __init__(self) -> None:
        """Initialize fake QApplication."""
        FakeQApplication._instance = self

    @classmethod
    def instance(cls) -> "FakeQApplication | None":
        """Get current QApplication instance.

        Returns:
            Current instance or None.
        """
        return cls._instance

    @classmethod
    def primaryScreen(cls) -> FakeScreen | None:
        """Get primary screen.

        Returns:
            Primary screen or None.
        """
        return cls._screen

    @classmethod
    def setTestScreen(cls, screen: FakeScreen | None) -> None:
        """Set test screen for testing.

        Args:
            screen: Screen to use for testing.
        """
        cls._screen = screen

    @classmethod
    def reset(cls) -> None:
        """Reset application state for testing."""
        cls._instance = None
        cls._screen = None


class FakeWidget:
    """Real widget simulator for testing window operations."""

    def __init__(self) -> None:
        """Initialize fake widget."""
        self._width = 100
        self._height = 100
        self._x = 0
        self._y = 0
        self._min_width = 0
        self._min_height = 0

    def resize(self, width: int, height: int) -> None:
        """Resize widget.

        Args:
            width: New width.
            height: New height.
        """
        self._width = width
        self._height = height

    def move(self, x: int, y: int) -> None:
        """Move widget to position.

        Args:
            x: X coordinate.
            y: Y coordinate.
        """
        self._x = x
        self._y = y

    def frameGeometry(self) -> FakeGeometry:
        """Get frame geometry.

        Returns:
            Frame geometry object.
        """
        return FakeGeometry(self._width, self._height, self._x, self._y)

    def x(self) -> int:
        """Get X position.

        Returns:
            X coordinate.
        """
        return self._x

    def y(self) -> int:
        """Get Y position.

        Returns:
            Y coordinate.
        """
        return self._y

    def width(self) -> int:
        """Get width.

        Returns:
            Width in pixels.
        """
        return self._width

    def height(self) -> int:
        """Get height.

        Returns:
            Height in pixels.
        """
        return self._height

    def setMinimumSize(self, width: int, height: int) -> None:
        """Set minimum size.

        Args:
            width: Minimum width.
            height: Minimum height.
        """
        self._min_width = width
        self._min_height = height

    def minimumWidth(self) -> int:
        """Get minimum width.

        Returns:
            Minimum width in pixels.
        """
        return self._min_width

    def minimumHeight(self) -> int:
        """Get minimum height.

        Returns:
            Minimum height in pixels.
        """
        return self._min_height


class TestGetDefaultWindowSize:
    """Test suite for get_default_window_size function."""

    def test_default_window_size_with_screen_1920x1080(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size calculated from 1920x1080 screen."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()

        assert width == int(1920 * 0.8)
        assert height == int(1080 * 0.8)
        assert width == 1536
        assert height == 864

        FakeQApplication.reset()

    def test_default_window_size_without_qapplication(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size returns minimum when no QApplication."""
        FakeQApplication.reset()

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()

        assert width == 800
        assert height == 600

    def test_default_window_size_without_screen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size returns minimum when no primary screen."""
        app = FakeQApplication()
        FakeQApplication.setTestScreen(None)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()

        assert width == 800
        assert height == 600

        FakeQApplication.reset()

    def test_default_window_size_custom_percentage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size respects custom width/height percentages."""
        app = FakeQApplication()
        screen = FakeScreen(2000, 1500)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(
            width_percentage=0.5,
            height_percentage=0.6,
        )

        assert width == 1000
        assert height == 900

        FakeQApplication.reset()

    def test_default_window_size_enforces_minimum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size enforces minimum dimensions."""
        app = FakeQApplication()
        screen = FakeScreen(500, 400)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(
            width_percentage=0.5,
            height_percentage=0.5,
            min_width=1000,
            min_height=800,
        )

        assert width == 1000
        assert height == 800

        FakeQApplication.reset()

    def test_default_window_size_various_resolutions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size works with various screen resolutions."""
        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        resolutions = [
            (1024, 768, 819, 614),
            (1366, 768, 1092, 614),
            (1920, 1080, 1536, 864),
            (2560, 1440, 2048, 1152),
            (3840, 2160, 3072, 1728),
        ]

        for screen_width, screen_height, expected_width, expected_height in resolutions:
            app = FakeQApplication()
            screen = FakeScreen(screen_width, screen_height)
            FakeQApplication.setTestScreen(screen)

            width, height = get_default_window_size()

            assert width == expected_width
            assert height == expected_height
            assert width > 0
            assert height > 0
            assert width <= screen_width
            assert height <= screen_height

            FakeQApplication.reset()

    def test_default_window_size_zero_percentage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size handles zero percentage correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(
            width_percentage=0.0, height_percentage=0.0, min_width=100, min_height=100
        )

        assert width == 100
        assert height == 100

        FakeQApplication.reset()

    def test_default_window_size_large_percentage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default window size handles large percentage values."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(
            width_percentage=1.5, height_percentage=1.5
        )

        assert width == int(1920 * 1.5)
        assert height == int(1080 * 1.5)
        assert width > 1920
        assert height > 1080

        FakeQApplication.reset()


class TestCenterWindowOnScreen:
    """Test suite for center_window_on_screen function."""

    def test_center_window_positions_correctly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Window is centered on primary screen."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080, 0, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        window.resize(800, 600)

        center_window_on_screen(window)

        expected_x = (1920 - 800) // 2
        expected_y = (1080 - 600) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y
        assert window.x() == 560
        assert window.y() == 240

        FakeQApplication.reset()

    def test_center_window_without_qapplication(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Centering window without QApplication does not crash."""
        FakeQApplication.reset()

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        original_x = window.x()
        original_y = window.y()

        center_window_on_screen(window)

        assert window.x() == original_x
        assert window.y() == original_y

    def test_center_window_without_screen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Centering window without primary screen does not crash."""
        app = FakeQApplication()
        FakeQApplication.setTestScreen(None)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        original_x = window.x()
        original_y = window.y()

        center_window_on_screen(window)

        assert window.x() == original_x
        assert window.y() == original_y

        FakeQApplication.reset()

    def test_center_window_with_offset_screen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Window centered correctly on screen with offset."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080, 100, 50)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        window.resize(800, 600)

        center_window_on_screen(window)

        expected_x = 100 + (1920 - 800) // 2
        expected_y = 50 + (1080 - 600) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y
        assert window.x() == 660
        assert window.y() == 290

        FakeQApplication.reset()

    def test_center_window_small_screen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Window centered on small screen."""
        app = FakeQApplication()
        screen = FakeScreen(1024, 768)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        window.resize(600, 400)

        center_window_on_screen(window)

        expected_x = (1024 - 600) // 2
        expected_y = (768 - 400) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y
        assert window.x() == 212
        assert window.y() == 184

        FakeQApplication.reset()

    def test_center_window_large_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Large window centered on screen."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        window.resize(1600, 900)

        center_window_on_screen(window)

        expected_x = (1920 - 1600) // 2
        expected_y = (1080 - 900) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y
        assert window.x() == 160
        assert window.y() == 90

        FakeQApplication.reset()


class TestGetDialogSize:
    """Test suite for get_dialog_size function."""

    def test_dialog_size_small(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Small dialog size calculated correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height, min_width, min_height = get_dialog_size("small")

        assert width == int(1920 * 0.4)
        assert height == int(1080 * 0.3)
        assert width == 768
        assert height == 324
        assert min_width == 400
        assert min_height == 200

        FakeQApplication.reset()

    def test_dialog_size_standard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Standard dialog size calculated correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height, min_width, min_height = get_dialog_size("standard")

        assert width == int(1920 * 0.6)
        assert height == int(1080 * 0.5)
        assert width == 1152
        assert height == 540
        assert min_width == 600
        assert min_height == 400

        FakeQApplication.reset()

    def test_dialog_size_large(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Large dialog size calculated correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height, min_width, min_height = get_dialog_size("large")

        assert width == int(1920 * 0.8)
        assert height == int(1080 * 0.7)
        assert width == 1536
        assert height == 756
        assert min_width == 800
        assert min_height == 600

        FakeQApplication.reset()

    def test_dialog_size_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Full dialog size calculated correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height, min_width, min_height = get_dialog_size("full")

        assert width == int(1920 * 0.9)
        assert height == int(1080 * 0.85)
        assert width == 1728
        assert height == 918
        assert min_width == 1000
        assert min_height == 700

        FakeQApplication.reset()

    def test_dialog_size_unknown_defaults_to_standard(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unknown dialog type defaults to standard size."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width1, height1, min_width1, min_height1 = get_dialog_size("unknown")
        width2, height2, min_width2, min_height2 = get_dialog_size("standard")

        assert width1 == width2
        assert height1 == height2
        assert min_width1 == min_width2
        assert min_height1 == min_height2

        FakeQApplication.reset()

    def test_dialog_size_enforces_minimum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog size enforces minimum dimensions."""
        app = FakeQApplication()
        screen = FakeScreen(800, 600)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height, min_width, min_height = get_dialog_size("large")

        assert width >= min_width
        assert height >= min_height
        assert width == 800
        assert height == 600
        assert min_width == 800
        assert min_height == 600

        FakeQApplication.reset()

    def test_dialog_size_all_types_on_small_screen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """All dialog types work correctly on small screen."""
        app = FakeQApplication()
        screen = FakeScreen(1024, 768)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        expected = {
            "small": (409, 230, 400, 200),
            "standard": (614, 384, 600, 400),
            "large": (819, 537, 800, 600),
            "full": (921, 652, 1000, 700),
        }

        for dialog_type, (exp_w, exp_h, exp_min_w, exp_min_h) in expected.items():
            width, height, min_width, min_height = get_dialog_size(dialog_type)
            assert width == exp_w
            assert height == exp_h
            assert min_width == exp_min_w
            assert min_height == exp_min_h

        FakeQApplication.reset()


class TestApplyDialogSizing:
    """Test suite for apply_dialog_sizing function."""

    def test_apply_dialog_sizing_sets_size(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog sizing sets minimum size and resizes dialog."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()

        apply_dialog_sizing(dialog, "standard")

        assert dialog.minimumWidth() == 600
        assert dialog.minimumHeight() == 400
        assert dialog.width() == 1152
        assert dialog.height() == 540

        FakeQApplication.reset()

    def test_apply_dialog_sizing_centers_dialog(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog sizing centers dialog on screen."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()

        apply_dialog_sizing(dialog, "standard")

        expected_x = (1920 - dialog.width()) // 2
        expected_y = (1080 - dialog.height()) // 2

        assert dialog.x() == expected_x
        assert dialog.y() == expected_y
        assert dialog.x() == 384
        assert dialog.y() == 270

        FakeQApplication.reset()

    def test_apply_dialog_sizing_respects_dialog_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog sizing passes dialog type correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()

        apply_dialog_sizing(dialog, "large")

        assert dialog.minimumWidth() == 800
        assert dialog.minimumHeight() == 600
        assert dialog.width() == 1536
        assert dialog.height() == 756

        FakeQApplication.reset()

    def test_apply_dialog_sizing_all_types(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog sizing works with all dialog types."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog_types = ["small", "standard", "large", "full"]
        expected_sizes = {
            "small": (768, 324, 400, 200),
            "standard": (1152, 540, 600, 400),
            "large": (1536, 756, 800, 600),
            "full": (1728, 918, 1000, 700),
        }

        for dialog_type in dialog_types:
            dialog = FakeWidget()
            apply_dialog_sizing(dialog, dialog_type)

            exp_w, exp_h, exp_min_w, exp_min_h = expected_sizes[dialog_type]
            assert dialog.width() == exp_w
            assert dialog.height() == exp_h
            assert dialog.minimumWidth() == exp_min_w
            assert dialog.minimumHeight() == exp_min_h

        FakeQApplication.reset()


class TestWindowSizingIntegration:
    """Integration tests for window sizing functionality."""

    def test_full_workflow_create_and_center_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Complete workflow of creating and centering window."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080, 0, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()
        window = FakeWidget()
        window.resize(width, height)

        center_window_on_screen(window)

        assert window.width() == int(1920 * 0.8)
        assert window.height() == int(1080 * 0.8)
        assert window.width() == 1536
        assert window.height() == 864
        assert window.x() >= 0
        assert window.y() >= 0
        assert window.x() == 192
        assert window.y() == 108

        FakeQApplication.reset()

    def test_full_workflow_create_and_size_dialog(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Complete workflow of creating and sizing dialog."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080, 0, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()

        apply_dialog_sizing(dialog, "standard")

        assert dialog.minimumWidth() == 600
        assert dialog.minimumHeight() == 400
        assert dialog.width() == int(1920 * 0.6)
        assert dialog.height() == int(1080 * 0.5)
        assert dialog.width() == 1152
        assert dialog.height() == 540

        FakeQApplication.reset()

    def test_multi_monitor_workflow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Workflow with multi-monitor offset screen."""
        app = FakeQApplication()
        screen = FakeScreen(2560, 1440, 1920, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()
        apply_dialog_sizing(dialog, "large")

        expected_x = 1920 + (2560 - dialog.width()) // 2
        expected_y = (1440 - dialog.height()) // 2

        assert dialog.x() == expected_x
        assert dialog.y() == expected_y

        FakeQApplication.reset()


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_screen_dimensions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing handles zero screen dimensions gracefully."""
        app = FakeQApplication()
        screen = FakeScreen(0, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(min_width=800, min_height=600)

        assert width == 800
        assert height == 600

        FakeQApplication.reset()

    def test_very_small_screen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing works with very small screen dimensions."""
        app = FakeQApplication()
        screen = FakeScreen(640, 480)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()

        assert width >= 800
        assert height >= 600
        assert width == 800
        assert height == 600

        FakeQApplication.reset()

    def test_very_large_screen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing works with very large screen dimensions."""
        app = FakeQApplication()
        screen = FakeScreen(7680, 4320)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size()

        assert width == int(7680 * 0.8)
        assert height == int(4320 * 0.8)
        assert width == 6144
        assert height == 3456
        assert width > 0
        assert height > 0

        FakeQApplication.reset()

    def test_extreme_percentage_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing handles extreme percentage values correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        width, height = get_default_window_size(
            width_percentage=0.0,
            height_percentage=0.0,
            min_width=100,
            min_height=100,
        )

        assert width == 100
        assert height == 100

        width, height = get_default_window_size(
            width_percentage=1.5,
            height_percentage=1.5,
        )

        assert width > 0
        assert height > 0
        assert width == int(1920 * 1.5)
        assert height == int(1080 * 1.5)

        FakeQApplication.reset()

    def test_negative_screen_offset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sizing handles negative screen offsets correctly."""
        app = FakeQApplication()
        screen = FakeScreen(1920, 1080, -1920, 0)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        window = FakeWidget()
        window.resize(800, 600)

        center_window_on_screen(window)

        expected_x = -1920 + (1920 - 800) // 2
        expected_y = (1080 - 600) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y
        assert window.x() == -1360
        assert window.y() == 240

        FakeQApplication.reset()

    def test_dialog_sizing_on_ultra_wide_screen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dialog sizing works correctly on ultra-wide screen."""
        app = FakeQApplication()
        screen = FakeScreen(3440, 1440)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()
        apply_dialog_sizing(dialog, "standard")

        assert dialog.width() == int(3440 * 0.6)
        assert dialog.height() == int(1440 * 0.5)
        assert dialog.width() == 2064
        assert dialog.height() == 720

        FakeQApplication.reset()

    def test_minimum_size_larger_than_calculated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Minimum size is enforced when larger than calculated size."""
        app = FakeQApplication()
        screen = FakeScreen(1000, 800)
        FakeQApplication.setTestScreen(screen)

        monkeypatch.setattr(
            "intellicrack.ui.window_sizing.QApplication", FakeQApplication
        )

        dialog = FakeWidget()
        apply_dialog_sizing(dialog, "full")

        assert dialog.width() >= dialog.minimumWidth()
        assert dialog.height() >= dialog.minimumHeight()
        assert dialog.minimumWidth() == 1000
        assert dialog.minimumHeight() == 700
        assert dialog.width() == 1000
        assert dialog.height() == 700

        FakeQApplication.reset()


@pytest.mark.skipif(not HAS_QT, reason="PyQt6 not available")
class TestRealQtIntegration:
    """Integration tests with real Qt widgets when available."""

    def test_real_qt_widget_sizing(self, qtbot: Any) -> None:
        """Test window sizing with real Qt widget."""
        if QWidget is None:
            pytest.skip("QWidget not available")

        widget = QWidget()
        qtbot.addWidget(widget)

        width, height = get_default_window_size()
        widget.resize(width, height)

        assert widget.width() == width
        assert widget.height() == height
        assert widget.width() > 0
        assert widget.height() > 0

    def test_real_qt_dialog_sizing(self, qtbot: Any) -> None:
        """Test dialog sizing with real Qt dialog."""
        if QDialog is None:
            pytest.skip("QDialog not available")

        dialog = QDialog()
        qtbot.addWidget(dialog)

        apply_dialog_sizing(dialog, "standard")

        assert dialog.minimumWidth() > 0
        assert dialog.minimumHeight() > 0
        assert dialog.width() >= dialog.minimumWidth()
        assert dialog.height() >= dialog.minimumHeight()

    def test_real_qt_centering(self, qtbot: Any) -> None:
        """Test window centering with real Qt widget."""
        if QWidget is None or QApplication is None:
            pytest.skip("Qt not available")

        if not QApplication.instance():
            pytest.skip("No QApplication instance")

        widget = QWidget()
        qtbot.addWidget(widget)
        widget.resize(800, 600)

        center_window_on_screen(widget)

        assert widget.x() >= 0 or widget.y() >= 0
