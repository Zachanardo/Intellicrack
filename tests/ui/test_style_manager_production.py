"""Production tests for Style Manager.

Validates centralized styling, object name mapping, and widget styling functions.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QFrame, QLabel, QProgressBar, QPushButton, QTextEdit, QWidget
from intellicrack.ui.style_manager import StyleManager


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    existing_app = QApplication.instance()
    if existing_app is None:
        return QApplication([])
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    return existing_app


class TestStyleManagerMappings:
    """Test style mapping definitions."""

    def test_style_mappings_defined(self) -> None:
        """STYLE_MAPPINGS dictionary is defined and populated."""
        assert hasattr(StyleManager, "STYLE_MAPPINGS")
        assert isinstance(StyleManager.STYLE_MAPPINGS, dict)
        assert len(StyleManager.STYLE_MAPPINGS) > 0

    def test_status_styles_exist(self) -> None:
        """Status label styles are defined."""
        status_styles = [
            "status_success",
            "status_error",
            "status_warning",
            "status_info",
            "status_neutral",
        ]
        for style in status_styles:
            assert style in StyleManager.STYLE_MAPPINGS

    def test_header_styles_exist(self) -> None:
        """Header and title styles are defined."""
        header_styles = ["header_bold", "title_large", "title_medium", "subtitle"]
        for style in header_styles:
            assert style in StyleManager.STYLE_MAPPINGS

    def test_button_styles_exist(self) -> None:
        """Button styles are defined."""
        button_styles = [
            "primary_button",
            "secondary_button",
            "danger_button",
            "warning_button",
        ]
        for style in button_styles:
            assert style in StyleManager.STYLE_MAPPINGS

    def test_progress_bar_styles_exist(self) -> None:
        """Progress bar styles are defined."""
        progress_styles = [
            "loading_progress",
            "failed_progress",
            "pending_progress",
            "completed_progress",
        ]
        for style in progress_styles:
            assert style in StyleManager.STYLE_MAPPINGS


class TestApplyStyle:
    """Test apply_style method."""

    def test_apply_style_sets_object_name(self, qapp: QApplication) -> None:
        """apply_style sets correct object name on widget."""
        widget = QWidget()
        StyleManager.apply_style(widget, "status_success")

        assert widget.objectName() == "statusSuccess"

    def test_apply_style_with_invalid_name(self, qapp: QApplication) -> None:
        """apply_style with invalid name does not crash."""
        widget = QWidget()
        original_name = widget.objectName()

        StyleManager.apply_style(widget, "nonexistent_style")

        assert widget.objectName() == original_name

    def test_apply_style_overwrites_previous_name(self, qapp: QApplication) -> None:
        """apply_style overwrites previous object name."""
        widget = QWidget()
        widget.setObjectName("previous_name")

        StyleManager.apply_style(widget, "status_error")

        assert widget.objectName() == "statusError"

    def test_apply_style_to_different_widgets(self, qapp: QApplication) -> None:
        """apply_style works on different widget types."""
        label = QLabel()
        button = QPushButton()
        frame = QFrame()

        StyleManager.apply_style(label, "header_bold")
        StyleManager.apply_style(button, "primary_button")
        StyleManager.apply_style(frame, "content_panel")

        assert label.objectName() == "headerBold"
        assert button.objectName() == "primaryButton"
        assert frame.objectName() == "contentPanel"


class TestStyleLabel:
    """Test style_label method."""

    def test_style_label_applies_style(self, qapp: QApplication) -> None:
        """style_label applies correct style to label."""
        label = QLabel("Test Label")
        StyleManager.style_label(label, "status_success")

        assert label.objectName() == "statusSuccess"

    def test_style_label_with_header_styles(self, qapp: QApplication) -> None:
        """style_label applies header styles correctly."""
        label = QLabel("Header")
        StyleManager.style_label(label, "header_bold")

        assert label.objectName() == "headerBold"

    def test_style_label_with_description_styles(self, qapp: QApplication) -> None:
        """style_label applies description styles correctly."""
        label = QLabel("Description")
        StyleManager.style_label(label, "description_text")

        assert label.objectName() == "descriptionText"


class TestStyleButton:
    """Test style_button method."""

    def test_style_button_applies_primary(self, qapp: QApplication) -> None:
        """style_button applies primary button style."""
        button = QPushButton("Primary")
        StyleManager.style_button(button, "primary_button")

        assert button.objectName() == "primaryButton"

    def test_style_button_applies_danger(self, qapp: QApplication) -> None:
        """style_button applies danger button style."""
        button = QPushButton("Delete")
        StyleManager.style_button(button, "danger_button")

        assert button.objectName() == "dangerButton"

    def test_style_button_with_action_styles(self, qapp: QApplication) -> None:
        """style_button applies action-specific styles."""
        button = QPushButton("Generate")
        StyleManager.style_button(button, "generate_button")

        assert button.objectName() == "generateButton"


class TestStyleProgress:
    """Test style_progress method."""

    def test_style_progress_applies_style(self, qapp: QApplication) -> None:
        """style_progress applies style to progress bar."""
        progress = QProgressBar()
        StyleManager.style_progress(progress, "loading_progress")

        assert progress.objectName() == "loadingProgress"

    def test_style_progress_with_state_styles(self, qapp: QApplication) -> None:
        """style_progress applies different state styles."""
        progress = QProgressBar()

        StyleManager.style_progress(progress, "pending_progress")
        assert progress.objectName() == "pendingProgress"

        StyleManager.style_progress(progress, "completed_progress")
        assert progress.objectName() == "completedProgress"

    def test_style_progress_cpu_styles(self, qapp: QApplication) -> None:
        """style_progress applies CPU usage styles."""
        progress = QProgressBar()

        StyleManager.style_progress(progress, "cpu_high")
        assert progress.objectName() == "cpuHigh"

        StyleManager.style_progress(progress, "cpu_medium")
        assert progress.objectName() == "cpuMedium"


class TestStyleTextEdit:
    """Test style_text_edit method."""

    def test_style_text_edit_applies_style(self, qapp: QApplication) -> None:
        """style_text_edit applies style to text edit."""
        text_edit = QTextEdit()
        StyleManager.style_text_edit(text_edit, "console_output")

        assert text_edit.objectName() == "consoleOutput"

    def test_style_text_edit_with_preview_style(self, qapp: QApplication) -> None:
        """style_text_edit applies preview text style."""
        text_edit = QTextEdit()
        StyleManager.style_text_edit(text_edit, "preview_text")

        assert text_edit.objectName() == "previewText"


class TestStyleFrame:
    """Test style_frame method."""

    def test_style_frame_applies_style(self, qapp: QApplication) -> None:
        """style_frame applies style to frame."""
        frame = QFrame()
        StyleManager.style_frame(frame, "stats_frame")

        assert frame.objectName() == "statsFrame"

    def test_style_frame_with_panel_styles(self, qapp: QApplication) -> None:
        """style_frame applies panel styles."""
        frame = QFrame()
        StyleManager.style_frame(frame, "content_panel")

        assert frame.objectName() == "contentPanel"


class TestUpdateStatusStyle:
    """Test update_status_style method."""

    def test_update_status_style_success(self, qapp: QApplication) -> None:
        """update_status_style applies success style."""
        label = QLabel()
        StyleManager.update_status_style(label, "success")

        assert label.objectName() == "statusSuccess"

    def test_update_status_style_error(self, qapp: QApplication) -> None:
        """update_status_style applies error style."""
        label = QLabel()
        StyleManager.update_status_style(label, "error")

        assert label.objectName() == "statusError"

    def test_update_status_style_warning(self, qapp: QApplication) -> None:
        """update_status_style applies warning style."""
        label = QLabel()
        StyleManager.update_status_style(label, "warning")

        assert label.objectName() == "statusWarning"

    def test_update_status_style_info(self, qapp: QApplication) -> None:
        """update_status_style applies info style."""
        label = QLabel()
        StyleManager.update_status_style(label, "info")

        assert label.objectName() == "statusInfo"

    def test_update_status_style_installed(self, qapp: QApplication) -> None:
        """update_status_style handles installed status."""
        label = QLabel()
        StyleManager.update_status_style(label, "installed")

        assert label.objectName() == "installedStatus"

    def test_update_status_style_unknown_defaults_neutral(self, qapp: QApplication) -> None:
        """update_status_style defaults to neutral for unknown status."""
        label = QLabel()
        StyleManager.update_status_style(label, "unknown_status")

        assert label.objectName() == "statusNeutral"


class TestUpdateProgressStyle:
    """Test update_progress_style method."""

    def test_update_progress_style_loading(self, qapp: QApplication) -> None:
        """update_progress_style applies loading state."""
        progress = QProgressBar()
        StyleManager.update_progress_style(progress, "loading")

        assert progress.objectName() == "loadingProgress"

    def test_update_progress_style_failed(self, qapp: QApplication) -> None:
        """update_progress_style applies failed state."""
        progress = QProgressBar()
        StyleManager.update_progress_style(progress, "failed")

        assert progress.objectName() == "failedProgress"

    def test_update_progress_style_completed(self, qapp: QApplication) -> None:
        """update_progress_style applies completed state."""
        progress = QProgressBar()
        StyleManager.update_progress_style(progress, "completed")

        assert progress.objectName() == "completedProgress"


class TestCPUProgressStyle:
    """Test update_cpu_progress_style method."""

    def test_cpu_progress_high_usage(self, qapp: QApplication) -> None:
        """CPU progress shows high usage style for >= 80%."""
        progress = QProgressBar()
        StyleManager.update_cpu_progress_style(progress, 85.0)

        assert progress.objectName() == "cpuHigh"

    def test_cpu_progress_medium_usage(self, qapp: QApplication) -> None:
        """CPU progress shows medium usage style for 50-79%."""
        progress = QProgressBar()
        StyleManager.update_cpu_progress_style(progress, 65.0)

        assert progress.objectName() == "cpuMedium"

    def test_cpu_progress_normal_usage(self, qapp: QApplication) -> None:
        """CPU progress shows normal usage style for < 50%."""
        progress = QProgressBar()
        StyleManager.update_cpu_progress_style(progress, 30.0)

        assert progress.objectName() == "cpuNormal"

    def test_cpu_progress_boundary_80(self, qapp: QApplication) -> None:
        """CPU progress at 80% uses high style."""
        progress = QProgressBar()
        StyleManager.update_cpu_progress_style(progress, 80.0)

        assert progress.objectName() == "cpuHigh"

    def test_cpu_progress_boundary_50(self, qapp: QApplication) -> None:
        """CPU progress at 50% uses medium style."""
        progress = QProgressBar()
        StyleManager.update_cpu_progress_style(progress, 50.0)

        assert progress.objectName() == "cpuMedium"


class TestGPUProgressStyle:
    """Test update_gpu_progress_style method."""

    def test_gpu_progress_high_usage(self, qapp: QApplication) -> None:
        """GPU progress shows high usage style for >= 80%."""
        progress = QProgressBar()
        StyleManager.update_gpu_progress_style(progress, 90.0)

        assert progress.objectName() == "gpuHigh"

    def test_gpu_progress_medium_usage(self, qapp: QApplication) -> None:
        """GPU progress shows medium usage style for 50-79%."""
        progress = QProgressBar()
        StyleManager.update_gpu_progress_style(progress, 60.0)

        assert progress.objectName() == "gpuMedium"

    def test_gpu_progress_normal_usage(self, qapp: QApplication) -> None:
        """GPU progress shows normal usage style for < 50%."""
        progress = QProgressBar()
        StyleManager.update_gpu_progress_style(progress, 25.0)

        assert progress.objectName() == "gpuNormal"


class TestMemoryProgressStyle:
    """Test update_memory_progress_style method."""

    def test_memory_progress_high_usage(self, qapp: QApplication) -> None:
        """Memory progress shows high usage style for >= 80%."""
        progress = QProgressBar()
        StyleManager.update_memory_progress_style(progress, 85.0)

        assert progress.objectName() == "memoryHigh"

    def test_memory_progress_medium_usage(self, qapp: QApplication) -> None:
        """Memory progress shows medium usage style for 50-79%."""
        progress = QProgressBar()
        StyleManager.update_memory_progress_style(progress, 70.0)

        assert progress.objectName() == "cpuMedium"

    def test_memory_progress_normal_usage(self, qapp: QApplication) -> None:
        """Memory progress shows normal usage style for < 50%."""
        progress = QProgressBar()
        StyleManager.update_memory_progress_style(progress, 40.0)

        assert progress.objectName() == "cpuNormal"


class TestDropZoneStyle:
    """Test style_drop_zone method."""

    def test_drop_zone_active_style(self, qapp: QApplication) -> None:
        """Drop zone applies active style."""
        widget = QWidget()
        StyleManager.style_drop_zone(widget, active=True)

        assert widget.objectName() == "dropZoneActive"

    def test_drop_zone_inactive_style(self, qapp: QApplication) -> None:
        """Drop zone applies inactive style."""
        widget = QWidget()
        StyleManager.style_drop_zone(widget, active=False)

        assert widget.objectName() == "dropZoneInactive"

    def test_drop_zone_toggle(self, qapp: QApplication) -> None:
        """Drop zone style can be toggled."""
        widget = QWidget()

        StyleManager.style_drop_zone(widget, active=True)
        assert widget.objectName() == "dropZoneActive"

        StyleManager.style_drop_zone(widget, active=False)
        assert widget.objectName() == "dropZoneInactive"


class TestRemoveInlineStyles:
    """Test remove_inline_styles method."""

    def test_remove_inline_styles_clears_stylesheet(self, qapp: QApplication) -> None:
        """remove_inline_styles clears widget stylesheet."""
        widget = QWidget()
        widget.setStyleSheet("background-color: red; color: white;")

        StyleManager.remove_inline_styles(widget)

        assert widget.styleSheet() == ""

    def test_remove_inline_styles_on_clean_widget(self, qapp: QApplication) -> None:
        """remove_inline_styles on widget without styles does nothing."""
        widget = QWidget()
        StyleManager.remove_inline_styles(widget)

        assert widget.styleSheet() == ""


class TestBatchApplyStyles:
    """Test batch_apply_styles method."""

    def test_batch_apply_styles_applies_to_all(self, qapp: QApplication) -> None:
        """batch_apply_styles applies styles to all widgets."""
        label1 = QLabel()
        label2 = QLabel()
        button = QPushButton()

        widgets = {
            label1: "status_success",
            label2: "status_error",
            button: "primary_button",
        }

        StyleManager.batch_apply_styles(widgets)

        assert label1.objectName() == "statusSuccess"
        assert label2.objectName() == "statusError"
        assert button.objectName() == "primaryButton"

    def test_batch_apply_styles_empty_dict(self, qapp: QApplication) -> None:
        """batch_apply_styles with empty dict does nothing."""
        StyleManager.batch_apply_styles({})

    def test_batch_apply_styles_single_widget(self, qapp: QApplication) -> None:
        """batch_apply_styles works with single widget."""
        widget = QWidget()
        StyleManager.batch_apply_styles({widget: "content_panel"})

        assert widget.objectName() == "contentPanel"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_style_manager_is_class_only(self) -> None:
        """StyleManager is used as class with no instances needed."""
        assert hasattr(StyleManager, "apply_style")
        assert hasattr(StyleManager, "style_label")
        assert hasattr(StyleManager, "batch_apply_styles")

    def test_multiple_style_applications(self, qapp: QApplication) -> None:
        """Multiple style applications overwrite previous styles."""
        widget = QWidget()

        StyleManager.apply_style(widget, "status_success")
        assert widget.objectName() == "statusSuccess"

        StyleManager.apply_style(widget, "status_error")
        assert widget.objectName() == "statusError"

    def test_style_name_case_sensitivity(self, qapp: QApplication) -> None:
        """Style names are case-sensitive."""
        widget = QWidget()
        original_name = widget.objectName()

        StyleManager.apply_style(widget, "STATUS_SUCCESS")

        assert widget.objectName() == original_name
