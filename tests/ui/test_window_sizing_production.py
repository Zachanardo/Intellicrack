"""Production tests for window sizing utilities.

This module tests the window sizing and positioning functions that
provide responsive UI design based on screen dimensions.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import pytest
from unittest.mock import MagicMock, patch

from intellicrack.ui.window_sizing import (
    apply_dialog_sizing,
    center_window_on_screen,
    get_default_window_size,
    get_dialog_size,
)
from intellicrack.handlers.pyqt6_handler import QApplication, QDialog, QWidget


class TestGetDefaultWindowSize:
    """Test suite for get_default_window_size function."""

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_default_window_size_with_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size calculated from screen dimensions."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 1920
        mock_rect.height.return_value = 1080
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size()

        assert width == int(1920 * 0.8)
        assert height == int(1080 * 0.8)

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    def test_default_window_size_without_qapplication(
        self,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size returns minimum when no QApplication."""
        mock_instance.return_value = None

        width, height = get_default_window_size()

        assert width == 800
        assert height == 600

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_default_window_size_without_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size returns minimum when no primary screen."""
        mock_instance.return_value = MagicMock()
        mock_primary_screen.return_value = None

        width, height = get_default_window_size()

        assert width == 800
        assert height == 600

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_default_window_size_custom_percentage(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size respects custom width/height percentages."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 2000
        mock_rect.height.return_value = 1500
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size(
            width_percentage=0.5,
            height_percentage=0.6,
        )

        assert width == 1000
        assert height == 900

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_default_window_size_enforces_minimum(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size enforces minimum dimensions."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 500
        mock_rect.height.return_value = 400
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size(
            width_percentage=0.5,
            height_percentage=0.5,
            min_width=1000,
            min_height=800,
        )

        assert width == 1000
        assert height == 800

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_default_window_size_various_resolutions(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Default window size works with various screen resolutions."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        resolutions = [
            (1024, 768),
            (1366, 768),
            (1920, 1080),
            (2560, 1440),
            (3840, 2160),
        ]

        for screen_width, screen_height in resolutions:
            mock_rect.width.return_value = screen_width
            mock_rect.height.return_value = screen_height

            width, height = get_default_window_size()

            assert width > 0
            assert height > 0
            assert width <= screen_width
            assert height <= screen_height


class TestCenterWindowOnScreen:
    """Test suite for center_window_on_screen function."""

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_center_window_positions_correctly(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Window is centered on primary screen."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 1920
        mock_rect.height.return_value = 1080
        mock_rect.x.return_value = 0
        mock_rect.y.return_value = 0
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        window = QWidget()
        window.resize(800, 600)
        qtbot.addWidget(window)

        center_window_on_screen(window)

        expected_x = (1920 - window.frameGeometry().width()) // 2
        expected_y = (1080 - window.frameGeometry().height()) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    def test_center_window_without_qapplication(
        self,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Centering window without QApplication does not crash."""
        mock_instance.return_value = None

        window = QWidget()
        qtbot.addWidget(window)

        try:
            center_window_on_screen(window)
        except Exception as e:
            pytest.fail(f"center_window_on_screen raised exception: {e}")

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_center_window_without_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Centering window without primary screen does not crash."""
        mock_instance.return_value = MagicMock()
        mock_primary_screen.return_value = None

        window = QWidget()
        qtbot.addWidget(window)

        try:
            center_window_on_screen(window)
        except Exception as e:
            pytest.fail(f"center_window_on_screen raised exception: {e}")

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_center_window_with_offset_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Window centered correctly on screen with offset."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 1920
        mock_rect.height.return_value = 1080
        mock_rect.x.return_value = 100
        mock_rect.y.return_value = 50
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        window = QWidget()
        window.resize(800, 600)
        qtbot.addWidget(window)

        center_window_on_screen(window)

        expected_x = 100 + (1920 - window.frameGeometry().width()) // 2
        expected_y = 50 + (1080 - window.frameGeometry().height()) // 2

        assert window.x() == expected_x
        assert window.y() == expected_y


class TestGetDialogSize:
    """Test suite for get_dialog_size function."""

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_small(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Small dialog size calculated correctly."""
        mock_get_size.return_value = (1920, 1080)

        width, height, min_width, min_height = get_dialog_size("small")

        assert width == int(1920 * 0.4)
        assert height == int(1080 * 0.3)
        assert min_width == 400
        assert min_height == 200

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_standard(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Standard dialog size calculated correctly."""
        mock_get_size.return_value = (1920, 1080)

        width, height, min_width, min_height = get_dialog_size("standard")

        assert width == int(1920 * 0.6)
        assert height == int(1080 * 0.5)
        assert min_width == 600
        assert min_height == 400

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_large(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Large dialog size calculated correctly."""
        mock_get_size.return_value = (1920, 1080)

        width, height, min_width, min_height = get_dialog_size("large")

        assert width == int(1920 * 0.8)
        assert height == int(1080 * 0.7)
        assert min_width == 800
        assert min_height == 600

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_full(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Full dialog size calculated correctly."""
        mock_get_size.return_value = (1920, 1080)

        width, height, min_width, min_height = get_dialog_size("full")

        assert width == int(1920 * 0.9)
        assert height == int(1080 * 0.85)
        assert min_width == 1000
        assert min_height == 700

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_unknown_defaults_to_standard(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Unknown dialog type defaults to standard size."""
        mock_get_size.return_value = (1920, 1080)

        width1, height1, min_width1, min_height1 = get_dialog_size("unknown")
        width2, height2, min_width2, min_height2 = get_dialog_size("standard")

        assert width1 == width2
        assert height1 == height2
        assert min_width1 == min_width2
        assert min_height1 == min_height2

    @patch("intellicrack.ui.window_sizing.get_default_window_size")
    def test_dialog_size_enforces_minimum(
        self,
        mock_get_size: MagicMock,
    ) -> None:
        """Dialog size enforces minimum dimensions."""
        mock_get_size.return_value = (800, 600)

        width, height, min_width, min_height = get_dialog_size("large")

        assert width >= min_width
        assert height >= min_height


class TestApplyDialogSizing:
    """Test suite for apply_dialog_sizing function."""

    @patch("intellicrack.ui.window_sizing.get_dialog_size")
    @patch("intellicrack.ui.window_sizing.center_window_on_screen")
    def test_apply_dialog_sizing_sets_size(
        self,
        mock_center: MagicMock,
        mock_get_size: MagicMock,
        qtbot: object,
    ) -> None:
        """Dialog sizing sets minimum size and resizes dialog."""
        mock_get_size.return_value = (800, 600, 400, 300)

        dialog = QDialog()
        qtbot.addWidget(dialog)

        apply_dialog_sizing(dialog, "standard")

        assert dialog.minimumWidth() == 400
        assert dialog.minimumHeight() == 300
        assert dialog.width() == 800
        assert dialog.height() == 600

    @patch("intellicrack.ui.window_sizing.get_dialog_size")
    @patch("intellicrack.ui.window_sizing.center_window_on_screen")
    def test_apply_dialog_sizing_centers_dialog(
        self,
        mock_center: MagicMock,
        mock_get_size: MagicMock,
        qtbot: object,
    ) -> None:
        """Dialog sizing centers dialog on screen."""
        mock_get_size.return_value = (800, 600, 400, 300)

        dialog = QDialog()
        qtbot.addWidget(dialog)

        apply_dialog_sizing(dialog, "standard")

        mock_center.assert_called_once_with(dialog)

    @patch("intellicrack.ui.window_sizing.get_dialog_size")
    @patch("intellicrack.ui.window_sizing.center_window_on_screen")
    def test_apply_dialog_sizing_respects_dialog_type(
        self,
        mock_center: MagicMock,
        mock_get_size: MagicMock,
        qtbot: object,
    ) -> None:
        """Dialog sizing passes dialog type to get_dialog_size."""
        mock_get_size.return_value = (1000, 800, 500, 400)

        dialog = QDialog()
        qtbot.addWidget(dialog)

        apply_dialog_sizing(dialog, "large")

        mock_get_size.assert_called_once_with("large")

    @patch("intellicrack.ui.window_sizing.get_dialog_size")
    @patch("intellicrack.ui.window_sizing.center_window_on_screen")
    def test_apply_dialog_sizing_all_types(
        self,
        mock_center: MagicMock,
        mock_get_size: MagicMock,
        qtbot: object,
    ) -> None:
        """Dialog sizing works with all dialog types."""
        dialog_types = ["small", "standard", "large", "full"]

        for dialog_type in dialog_types:
            mock_get_size.return_value = (800, 600, 400, 300)

            dialog = QDialog()
            qtbot.addWidget(dialog)

            try:
                apply_dialog_sizing(dialog, dialog_type)
            except Exception as e:
                pytest.fail(f"apply_dialog_sizing failed for {dialog_type}: {e}")


class TestWindowSizingIntegration:
    """Integration tests for window sizing functionality."""

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_full_workflow_create_and_center_window(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Complete workflow of creating and centering window."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 1920
        mock_rect.height.return_value = 1080
        mock_rect.x.return_value = 0
        mock_rect.y.return_value = 0
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size()
        window = QWidget()
        window.resize(width, height)
        qtbot.addWidget(window)

        center_window_on_screen(window)

        assert window.width() == int(1920 * 0.8)
        assert window.height() == int(1080 * 0.8)
        assert window.x() >= 0
        assert window.y() >= 0

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_full_workflow_create_and_size_dialog(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Complete workflow of creating and sizing dialog."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 1920
        mock_rect.height.return_value = 1080
        mock_rect.x.return_value = 0
        mock_rect.y.return_value = 0
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        dialog = QDialog()
        qtbot.addWidget(dialog)

        apply_dialog_sizing(dialog, "standard")

        assert dialog.minimumWidth() == 600
        assert dialog.minimumHeight() == 400
        assert dialog.width() == int(1920 * 0.6)
        assert dialog.height() == int(1080 * 0.5)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_zero_screen_dimensions(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Sizing handles zero screen dimensions gracefully."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 0
        mock_rect.height.return_value = 0
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size(min_width=800, min_height=600)

        assert width == 800
        assert height == 600

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_very_small_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Sizing works with very small screen dimensions."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 640
        mock_rect.height.return_value = 480
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size()

        assert width >= 800
        assert height >= 600

    @patch("intellicrack.ui.window_sizing.QApplication.instance")
    @patch("intellicrack.ui.window_sizing.QApplication.primaryScreen")
    def test_very_large_screen(
        self,
        mock_primary_screen: MagicMock,
        mock_instance: MagicMock,
    ) -> None:
        """Sizing works with very large screen dimensions."""
        mock_app = MagicMock()
        mock_instance.return_value = mock_app

        mock_screen = MagicMock()
        mock_rect = MagicMock()
        mock_rect.width.return_value = 7680
        mock_rect.height.return_value = 4320
        mock_screen.availableGeometry.return_value = mock_rect
        mock_primary_screen.return_value = mock_screen

        width, height = get_default_window_size()

        assert width == int(7680 * 0.8)
        assert height == int(4320 * 0.8)
        assert width > 0
        assert height > 0

    def test_extreme_percentage_values(self) -> None:
        """Sizing handles extreme percentage values correctly."""
        with patch("intellicrack.ui.window_sizing.QApplication.instance") as mock_instance:
            with patch("intellicrack.ui.window_sizing.QApplication.primaryScreen") as mock_primary_screen:
                mock_app = MagicMock()
                mock_instance.return_value = mock_app

                mock_screen = MagicMock()
                mock_rect = MagicMock()
                mock_rect.width.return_value = 1920
                mock_rect.height.return_value = 1080
                mock_screen.availableGeometry.return_value = mock_rect
                mock_primary_screen.return_value = mock_screen

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
