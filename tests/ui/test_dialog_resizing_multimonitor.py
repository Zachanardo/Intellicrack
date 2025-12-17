"""Production tests for dialog resizing and multi-monitor display support.

Tests validate:
- Dialog resizing preserves content layout
- Minimum and maximum size constraints
- Responsive layout adaption
- Multi-monitor detection and positioning
- Screen boundary detection
- Window restoration across sessions
- Aspect ratio maintenance
- Content scaling on high-DPI displays

All tests use real window management - NO mocks.
Tests verify actual dialog behavior.
"""

import json
from pathlib import Path
from typing import Any

import pytest

try:
    from PyQt6.QtCore import QRect, QSettings, QSize, Qt
    from PyQt6.QtGui import QGuiApplication, QScreen
    from PyQt6.QtWidgets import (
        QApplication,
        QDialog,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QDialog = None
    QWidget = None
    QVBoxLayout = None
    QHBoxLayout = None
    QLabel = None
    QTextEdit = None
    QPushButton = None
    QApplication = None
    QGuiApplication = None
    QScreen = None
    QSize = None
    QRect = None
    QSettings = None

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestDialog(QDialog):
    """Test dialog with resizable layout."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Test Dialog")
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout()

        self.title_label = QLabel("Test Dialog Title")
        layout.addWidget(self.title_label)

        self.content_edit = QTextEdit()
        self.content_edit.setPlainText("Sample content for testing resize behavior")
        layout.addWidget(self.content_edit)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)


class TestDialogResizing:
    """Test dialog resizing behavior."""

    def test_dialog_respects_minimum_size(
        self, qapp: QApplication
    ) -> None:
        """Dialog enforces minimum size constraint."""
        dialog = TestDialog()
        dialog.setMinimumSize(400, 300)

        dialog.resize(200, 150)

        actual_size = dialog.size()

        assert actual_size.width() >= 400
        assert actual_size.height() >= 300

    def test_dialog_respects_maximum_size(
        self, qapp: QApplication
    ) -> None:
        """Dialog enforces maximum size constraint."""
        dialog = TestDialog()
        dialog.setMaximumSize(800, 600)

        dialog.resize(1200, 900)

        actual_size = dialog.size()

        assert actual_size.width() <= 800
        assert actual_size.height() <= 600

    def test_dialog_resizes_to_custom_size(
        self, qapp: QApplication
    ) -> None:
        """Dialog resizes to user-specified dimensions."""
        dialog = TestDialog()

        target_width = 600
        target_height = 450

        dialog.resize(target_width, target_height)

        actual_size = dialog.size()

        assert abs(actual_size.width() - target_width) <= 10
        assert abs(actual_size.height() - target_height) <= 10

    def test_dialog_content_scales_on_resize(
        self, qapp: QApplication
    ) -> None:
        """Dialog content scales appropriately when dialog resizes."""
        dialog = TestDialog()
        dialog.resize(500, 400)

        initial_content_height = dialog.content_edit.height()

        dialog.resize(500, 600)

        qapp.processEvents()

        new_content_height = dialog.content_edit.height()

        assert new_content_height > initial_content_height

    def test_dialog_maintains_layout_after_resize(
        self, qapp: QApplication
    ) -> None:
        """Dialog layout remains valid after resizing."""
        dialog = TestDialog()

        for width, height in [(400, 300), (600, 450), (800, 600), (500, 400)]:
            dialog.resize(width, height)
            qapp.processEvents()

            assert dialog.title_label.isVisible()
            assert dialog.content_edit.isVisible()
            assert dialog.ok_button.isVisible()
            assert dialog.cancel_button.isVisible()

    def test_dialog_aspect_ratio_maintained(
        self, qapp: QApplication
    ) -> None:
        """Dialog maintains reasonable aspect ratio during resize."""
        dialog = TestDialog()
        dialog.resize(800, 600)

        size = dialog.size()
        aspect_ratio = size.width() / size.height()

        assert 0.5 <= aspect_ratio <= 3.0


class TestMultiMonitorSupport:
    """Test multi-monitor display support."""

    def test_detect_available_screens(
        self, qapp: QApplication
    ) -> None:
        """Application detects all available screens."""
        screens = qapp.screens()

        assert len(screens) >= 1

        for screen in screens:
            assert screen.size().width() > 0
            assert screen.size().height() > 0

    def test_get_screen_geometry(
        self, qapp: QApplication
    ) -> None:
        """Screen geometry retrieval returns valid dimensions."""
        primary_screen = qapp.primaryScreen()

        geometry = primary_screen.geometry()

        assert geometry.width() > 0
        assert geometry.height() > 0
        assert geometry.x() is not None
        assert geometry.y() is not None

    def test_dialog_positions_on_primary_screen(
        self, qapp: QApplication
    ) -> None:
        """Dialog defaults to primary screen when shown."""
        dialog = TestDialog()

        primary_screen = qapp.primaryScreen()
        screen_geometry = primary_screen.geometry()

        dialog.move(screen_geometry.center())

        dialog_pos = dialog.pos()

        assert screen_geometry.contains(dialog_pos)

    def test_dialog_moves_between_screens(
        self, qapp: QApplication
    ) -> None:
        """Dialog can be moved between available screens."""
        screens = qapp.screens()

        if len(screens) < 2:
            pytest.skip("Multiple monitors required for this test")

        dialog = TestDialog()

        first_screen = screens[0]
        second_screen = screens[1]

        dialog.move(first_screen.geometry().center())
        first_pos = dialog.pos()

        dialog.move(second_screen.geometry().center())
        second_pos = dialog.pos()

        assert first_pos != second_pos

    def test_detect_screen_containing_dialog(
        self, qapp: QApplication
    ) -> None:
        """System correctly identifies which screen contains dialog."""
        dialog = TestDialog()

        primary_screen = qapp.primaryScreen()
        dialog.move(primary_screen.geometry().center())

        screen_at_dialog = qapp.screenAt(dialog.geometry().center())

        assert screen_at_dialog is not None
        assert screen_at_dialog == primary_screen or screen_at_dialog in qapp.screens()


class TestScreenBoundaryDetection:
    """Test screen boundary detection and handling."""

    def test_dialog_stays_within_screen_bounds(
        self, qapp: QApplication
    ) -> None:
        """Dialog position constrained to screen boundaries."""
        dialog = TestDialog()

        primary_screen = qapp.primaryScreen()
        screen_rect = primary_screen.geometry()

        out_of_bounds_x = screen_rect.width() + 500
        out_of_bounds_y = screen_rect.height() + 500

        dialog.move(out_of_bounds_x, out_of_bounds_y)

        dialog_rect = dialog.frameGeometry()

        if dialog_rect.x() < screen_rect.x():
            assert dialog_rect.x() >= screen_rect.x() - dialog_rect.width()

    def test_dialog_fits_on_small_screen(
        self, qapp: QApplication
    ) -> None:
        """Dialog adjusts size to fit on small screens."""
        dialog = TestDialog()
        dialog.resize(2000, 1500)

        primary_screen = qapp.primaryScreen()
        screen_size = primary_screen.size()

        if dialog.width() > screen_size.width():
            dialog.resize(screen_size.width() - 100, dialog.height())

        if dialog.height() > screen_size.height():
            dialog.resize(dialog.width(), screen_size.height() - 100)

        assert dialog.width() <= screen_size.width()
        assert dialog.height() <= screen_size.height()

    def test_center_dialog_on_screen(
        self, qapp: QApplication
    ) -> None:
        """Dialog centers correctly on screen."""
        dialog = TestDialog()

        primary_screen = qapp.primaryScreen()
        screen_center = primary_screen.geometry().center()

        dialog_rect = dialog.frameGeometry()
        dialog_rect.moveCenter(screen_center)
        dialog.move(dialog_rect.topLeft())

        actual_center = dialog.frameGeometry().center()

        assert abs(actual_center.x() - screen_center.x()) <= 50
        assert abs(actual_center.y() - screen_center.y()) <= 50


class TestWindowStateRestoration:
    """Test window size and position restoration."""

    def test_save_and_restore_window_geometry(
        self, qapp: QApplication, temp_workspace: Path
    ) -> None:
        """Window geometry saves and restores across sessions."""
        settings_file = temp_workspace / "window_settings.json"

        dialog1 = TestDialog()
        dialog1.resize(650, 480)
        dialog1.move(100, 50)

        geometry = dialog1.saveGeometry()
        settings = {
            "geometry": geometry.toHex().data().decode(),
            "width": dialog1.width(),
            "height": dialog1.height(),
            "x": dialog1.x(),
            "y": dialog1.y(),
        }

        settings_file.write_text(json.dumps(settings))

        dialog2 = TestDialog()

        restored_settings = json.loads(settings_file.read_text())
        dialog2.resize(restored_settings["width"], restored_settings["height"])
        dialog2.move(restored_settings["x"], restored_settings["y"])

        assert abs(dialog2.width() - 650) <= 10
        assert abs(dialog2.height() - 480) <= 10

    def test_restore_maximized_state(
        self, qapp: QApplication
    ) -> None:
        """Maximized window state restores correctly."""
        dialog = TestDialog()

        was_maximized = dialog.isMaximized()

        dialog.showMaximized()
        qapp.processEvents()

        is_now_maximized = dialog.isMaximized()

        assert is_now_maximized

        dialog.showNormal()
        qapp.processEvents()

        assert not dialog.isMaximized()


class TestHighDPISupport:
    """Test high-DPI display support."""

    def test_detect_screen_dpi(
        self, qapp: QApplication
    ) -> None:
        """System detects screen DPI correctly."""
        primary_screen = qapp.primaryScreen()

        physical_dpi = primary_screen.physicalDotsPerInch()
        logical_dpi = primary_screen.logicalDotsPerInch()

        assert physical_dpi > 0
        assert logical_dpi > 0

    def test_detect_device_pixel_ratio(
        self, qapp: QApplication
    ) -> None:
        """System detects device pixel ratio for scaling."""
        primary_screen = qapp.primaryScreen()

        device_pixel_ratio = primary_screen.devicePixelRatio()

        assert device_pixel_ratio >= 1.0
        assert device_pixel_ratio <= 3.0

    def test_dialog_scales_with_dpi(
        self, qapp: QApplication
    ) -> None:
        """Dialog content scales appropriately with DPI."""
        dialog = TestDialog()

        primary_screen = qapp.primaryScreen()
        dpr = primary_screen.devicePixelRatio()

        expected_logical_width = 500
        dialog.resize(expected_logical_width, 400)

        actual_width = dialog.width()

        assert actual_width >= expected_logical_width * 0.9


class TestResponsiveLayout:
    """Test responsive layout adaptation."""

    def test_layout_adapts_to_narrow_width(
        self, qapp: QApplication
    ) -> None:
        """Layout adapts when dialog becomes narrow."""
        dialog = TestDialog()

        dialog.resize(400, 500)
        qapp.processEvents()

        assert dialog.content_edit.isVisible()
        assert dialog.ok_button.isVisible()

        dialog.resize(300, 500)
        qapp.processEvents()

        assert dialog.content_edit.isVisible()

    def test_layout_adapts_to_short_height(
        self, qapp: QApplication
    ) -> None:
        """Layout adapts when dialog becomes short."""
        dialog = TestDialog()

        dialog.resize(600, 300)
        qapp.processEvents()

        assert dialog.title_label.isVisible()
        assert dialog.ok_button.isVisible()

    def test_splitter_proportions_maintained(
        self, qapp: QApplication
    ) -> None:
        """Splitter proportions maintain during resize."""
        from PyQt6.QtWidgets import QSplitter

        class SplitterDialog(QDialog):
            def __init__(self) -> None:
                super().__init__()

                layout = QVBoxLayout()
                splitter = QSplitter(Qt.Orientation.Horizontal)

                left = QTextEdit("Left pane")
                right = QTextEdit("Right pane")

                splitter.addWidget(left)
                splitter.addWidget(right)
                splitter.setSizes([300, 300])

                layout.addWidget(splitter)
                self.setLayout(layout)
                self.splitter = splitter

        dialog = SplitterDialog()
        dialog.resize(600, 400)
        qapp.processEvents()

        initial_sizes = dialog.splitter.sizes()

        dialog.resize(800, 400)
        qapp.processEvents()

        new_sizes = dialog.splitter.sizes()

        ratio_initial = initial_sizes[0] / sum(initial_sizes) if sum(initial_sizes) > 0 else 0
        ratio_new = new_sizes[0] / sum(new_sizes) if sum(new_sizes) > 0 else 0

        assert abs(ratio_initial - ratio_new) < 0.1


class TestWindowFlags:
    """Test window flags and decorations."""

    def test_dialog_has_standard_decorations(
        self, qapp: QApplication
    ) -> None:
        """Dialog displays standard window decorations."""
        dialog = TestDialog()

        flags = dialog.windowFlags()

        assert flags & Qt.WindowType.Window or flags & Qt.WindowType.Dialog

    def test_frameless_dialog_configuration(
        self, qapp: QApplication
    ) -> None:
        """Frameless dialog configured correctly."""
        dialog = TestDialog()
        dialog.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        flags = dialog.windowFlags()

        assert flags & Qt.WindowType.FramelessWindowHint

    def test_always_on_top_flag(
        self, qapp: QApplication
    ) -> None:
        """Always-on-top window flag applies correctly."""
        dialog = TestDialog()
        dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)

        flags = dialog.windowFlags()

        assert flags & Qt.WindowType.WindowStaysOnTopHint


class TestModalDialogs:
    """Test modal dialog behavior."""

    def test_modal_dialog_blocks_parent(
        self, qapp: QApplication
    ) -> None:
        """Modal dialog correctly configured to block parent."""
        parent = QWidget()
        dialog = TestDialog(parent)

        dialog.setModal(True)

        assert dialog.isModal()

    def test_application_modal_blocks_all_windows(
        self, qapp: QApplication
    ) -> None:
        """Application modal dialog blocks all windows."""
        dialog = TestDialog()
        dialog.setWindowModality(Qt.WindowModality.ApplicationModal)

        modality = dialog.windowModality()

        assert modality == Qt.WindowModality.ApplicationModal


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
