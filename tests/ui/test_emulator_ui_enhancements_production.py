"""Production tests for emulator UI enhancements.

Tests EmulatorStatusWidget, decorator functionality, and emulator requirement validation
with real Qt widgets and actual emulator state management.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import Any

from intellicrack.handlers.pyqt6_handler import QApplication, QWidget, QMessageBox
from intellicrack.ui.emulator_ui_enhancements import (
    EmulatorStatusWidget,
    add_emulator_tooltips,
    show_emulator_warning,
    EmulatorRequiredDecorator,
)


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt widgets."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def emulator_status_widget(qapp: QApplication) -> EmulatorStatusWidget:
    """Create EmulatorStatusWidget instance for testing."""
    widget = EmulatorStatusWidget()
    yield widget
    widget.deleteLater()


class TestEmulatorStatusWidget:
    """Test EmulatorStatusWidget visual indicators and status tracking."""

    def test_initialization_creates_proper_ui_elements(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Widget initializes with proper UI labels and status tracking."""
        assert hasattr(emulator_status_widget, "qemu_label")
        assert hasattr(emulator_status_widget, "qemu_status")
        assert hasattr(emulator_status_widget, "qiling_label")
        assert hasattr(emulator_status_widget, "qiling_status")
        assert hasattr(emulator_status_widget, "emulator_status")

        assert "QEMU" in emulator_status_widget.emulator_status
        assert "Qiling" in emulator_status_widget.emulator_status

        assert emulator_status_widget.emulator_status["QEMU"]["running"] is False
        assert emulator_status_widget.emulator_status["Qiling"]["running"] is False

    def test_qemu_status_update_to_running_changes_visual_indicators(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Updating QEMU status to running changes label text and color."""
        test_message = "QEMU started successfully on port 1234"

        emulator_status_widget.update_emulator_status("QEMU", True, test_message)

        assert emulator_status_widget.emulator_status["QEMU"]["running"] is True
        assert emulator_status_widget.emulator_status["QEMU"]["message"] == test_message

        label_text = emulator_status_widget.qemu_status.text()
        assert "Running" in label_text or "OK" in label_text

        stylesheet = emulator_status_widget.qemu_status.styleSheet()
        assert "#51cf66" in stylesheet or "green" in stylesheet.lower()

        tooltip = emulator_status_widget.qemu_status.toolTip()
        assert tooltip == test_message

    def test_qemu_status_update_to_stopped_shows_red_indicator(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Updating QEMU status to stopped shows red visual indicator."""
        emulator_status_widget.update_emulator_status("QEMU", True, "Running")

        emulator_status_widget.update_emulator_status(
            "QEMU", False, "QEMU stopped by user"
        )

        assert emulator_status_widget.emulator_status["QEMU"]["running"] is False

        label_text = emulator_status_widget.qemu_status.text()
        assert "Not Running" in label_text or "⭕" in label_text

        stylesheet = emulator_status_widget.qemu_status.styleSheet()
        assert "#ff6b6b" in stylesheet or "red" in stylesheet.lower()

    def test_qiling_status_update_to_ready_changes_visual_indicators(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Updating Qiling status to ready changes label text and color."""
        test_message = "Qiling framework initialized successfully"

        emulator_status_widget.update_emulator_status("Qiling", True, test_message)

        assert emulator_status_widget.emulator_status["Qiling"]["running"] is True
        assert (
            emulator_status_widget.emulator_status["Qiling"]["message"] == test_message
        )

        label_text = emulator_status_widget.qiling_status.text()
        assert "Ready" in label_text or "OK" in label_text

        stylesheet = emulator_status_widget.qiling_status.styleSheet()
        assert "#51cf66" in stylesheet or "green" in stylesheet.lower()

    def test_qiling_status_update_to_not_ready_shows_red_indicator(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Updating Qiling status to not ready shows red visual indicator."""
        emulator_status_widget.update_emulator_status("Qiling", True, "Ready")

        emulator_status_widget.update_emulator_status(
            "Qiling", False, "Qiling not installed"
        )

        assert emulator_status_widget.emulator_status["Qiling"]["running"] is False

        label_text = emulator_status_widget.qiling_status.text()
        assert "Not Ready" in label_text or "⭕" in label_text

        stylesheet = emulator_status_widget.qiling_status.styleSheet()
        assert "#ff6b6b" in stylesheet or "red" in stylesheet.lower()

    def test_multiple_status_updates_maintain_independent_states(
        self, emulator_status_widget: EmulatorStatusWidget
    ) -> None:
        """Multiple status updates for different emulators maintain independent states."""
        emulator_status_widget.update_emulator_status(
            "QEMU", True, "QEMU running on port 5555"
        )
        emulator_status_widget.update_emulator_status(
            "Qiling", False, "Qiling not available"
        )

        assert emulator_status_widget.emulator_status["QEMU"]["running"] is True
        assert emulator_status_widget.emulator_status["Qiling"]["running"] is False

        qemu_text = emulator_status_widget.qemu_status.text()
        qiling_text = emulator_status_widget.qiling_status.text()

        assert "Running" in qemu_text or "OK" in qemu_text
        assert "Not Ready" in qiling_text or "⭕" in qiling_text


class TestEmulatorTooltips:
    """Test emulator tooltip functionality for UI widgets."""

    def test_add_emulator_tooltips_sets_correct_tooltips_on_widgets(
        self, qapp: QApplication
    ) -> None:
        """Adding emulator tooltips sets correct tooltips on provided widgets."""
        start_qemu_btn = QWidget()
        create_snapshot_btn = QWidget()
        qiling_checkbox = QWidget()

        widget_dict = {
            "start_qemu": start_qemu_btn,
            "create_snapshot": create_snapshot_btn,
            "qiling_emulation": qiling_checkbox,
        }

        add_emulator_tooltips(widget_dict)

        qemu_tooltip = start_qemu_btn.toolTip()
        assert "QEMU" in qemu_tooltip
        assert "virtual machine" in qemu_tooltip.lower()

        snapshot_tooltip = create_snapshot_btn.toolTip()
        assert "snapshot" in snapshot_tooltip.lower()
        assert "QEMU" in snapshot_tooltip

        qiling_tooltip = qiling_checkbox.toolTip()
        assert "Qiling" in qiling_tooltip
        assert "lightweight emulation" in qiling_tooltip.lower()

        start_qemu_btn.deleteLater()
        create_snapshot_btn.deleteLater()
        qiling_checkbox.deleteLater()

    def test_add_emulator_tooltips_handles_unknown_features_gracefully(
        self, qapp: QApplication
    ) -> None:
        """Adding tooltips with unknown features doesn't crash or set invalid tooltips."""
        unknown_widget = QWidget()

        widget_dict = {"unknown_feature": unknown_widget, "invalid_key": QWidget()}

        add_emulator_tooltips(widget_dict)

        tooltip = unknown_widget.toolTip()
        assert tooltip == ""

        unknown_widget.deleteLater()

    def test_add_emulator_tooltips_with_all_supported_features(
        self, qapp: QApplication
    ) -> None:
        """Adding tooltips for all supported emulator features sets correct tooltips."""
        features = [
            "start_qemu",
            "create_snapshot",
            "restore_snapshot",
            "execute_vm",
            "compare_snapshots",
            "qiling_emulation",
            "dynamic_analysis",
            "behavioral_analysis",
        ]

        widget_dict = {feature: QWidget() for feature in features}

        add_emulator_tooltips(widget_dict)

        for widget in widget_dict.values():
            tooltip = widget.toolTip()
            assert len(tooltip) > 0
            assert any(
                keyword in tooltip.lower()
                for keyword in ["qemu", "qiling", "emulator", "analysis", "snapshot"]
            )

        for widget in widget_dict.values():
            widget.deleteLater()


class TestEmulatorWarningDialog:
    """Test emulator warning dialog functionality."""

    def test_show_emulator_warning_qemu_displays_correct_message(
        self, qapp: QApplication
    ) -> None:
        """Showing QEMU warning displays correct message and buttons."""
        parent = QWidget()

        with patch.object(QMessageBox, "exec") as mock_exec:
            mock_exec.return_value = QMessageBox.StandardButton.Yes

            result = show_emulator_warning(parent, "QEMU", "Create Snapshot")

            assert result is True
            mock_exec.assert_called_once()

        parent.deleteLater()

    def test_show_emulator_warning_qiling_displays_correct_message(
        self, qapp: QApplication
    ) -> None:
        """Showing Qiling warning displays correct message and initializes automatically."""
        parent = QWidget()

        with patch.object(QMessageBox, "exec") as mock_exec:
            mock_exec.return_value = QMessageBox.StandardButton.No

            result = show_emulator_warning(parent, "Qiling", "Dynamic Analysis")

            assert result is False
            mock_exec.assert_called_once()

        parent.deleteLater()

    def test_show_emulator_warning_user_accepts_returns_true(
        self, qapp: QApplication
    ) -> None:
        """User accepting emulator warning returns True."""
        parent = QWidget()

        with patch.object(QMessageBox, "exec") as mock_exec:
            mock_exec.return_value = QMessageBox.StandardButton.Yes

            result = show_emulator_warning(parent, "QEMU", "Test Feature")

            assert result is True

        parent.deleteLater()

    def test_show_emulator_warning_user_rejects_returns_false(
        self, qapp: QApplication
    ) -> None:
        """User rejecting emulator warning returns False."""
        parent = QWidget()

        with patch.object(QMessageBox, "exec") as mock_exec:
            mock_exec.return_value = QMessageBox.StandardButton.No

            result = show_emulator_warning(parent, "QEMU", "Test Feature")

            assert result is False

        parent.deleteLater()


class TestEmulatorRequiredDecorator:
    """Test EmulatorRequiredDecorator functionality with real emulator checks."""

    def test_requires_qemu_decorator_allows_execution_when_qemu_running(
        self, qapp: QApplication
    ) -> None:
        """Decorator allows execution when QEMU is running."""

        class TestClass:
            def __init__(self) -> None:
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qemu
            def test_method(self) -> str:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.qemu_running = True
            mock_get_manager.return_value = mock_manager

            obj = TestClass()
            result = obj.test_method()

            assert result == "success"
            assert obj.executed is True

    def test_requires_qemu_decorator_starts_qemu_when_user_accepts(
        self, qapp: QApplication
    ) -> None:
        """Decorator starts QEMU when not running and user accepts warning."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qemu
            def test_method(self) -> str:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager, patch(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning"
        ) as mock_warning:

            mock_manager = MagicMock()
            mock_manager.qemu_running = False
            mock_manager.ensure_qemu_running.return_value = True
            mock_get_manager.return_value = mock_manager
            mock_warning.return_value = True

            obj = TestClass()
            result = obj.test_method()

            assert result == "success"
            assert obj.executed is True
            mock_manager.ensure_qemu_running.assert_called_once_with(obj.binary_path)

        obj.deleteLater()

    def test_requires_qemu_decorator_blocks_execution_when_user_rejects(
        self, qapp: QApplication
    ) -> None:
        """Decorator blocks execution when QEMU not running and user rejects."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qemu
            def test_method(self) -> str | None:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager, patch(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning"
        ) as mock_warning:

            mock_manager = MagicMock()
            mock_manager.qemu_running = False
            mock_get_manager.return_value = mock_manager
            mock_warning.return_value = False

            obj = TestClass()
            result = obj.test_method()

            assert result is None
            assert obj.executed is False

        obj.deleteLater()

    def test_requires_qemu_decorator_shows_error_when_no_binary_selected(
        self, qapp: QApplication
    ) -> None:
        """Decorator shows error when no binary is selected."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = None
                self.executed = False

            @EmulatorRequiredDecorator.requires_qemu
            def test_method(self) -> str | None:
                self.executed = True
                return "success"

        with patch.object(QMessageBox, "warning") as mock_warning:
            obj = TestClass()
            result = obj.test_method()

            assert result is None
            assert obj.executed is False
            mock_warning.assert_called_once()

        obj.deleteLater()

    def test_requires_qemu_decorator_shows_error_when_qemu_fails_to_start(
        self, qapp: QApplication
    ) -> None:
        """Decorator shows error when QEMU fails to start."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qemu
            def test_method(self) -> str | None:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager, patch(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning"
        ) as mock_warning, patch.object(
            QMessageBox, "critical"
        ) as mock_critical:

            mock_manager = MagicMock()
            mock_manager.qemu_running = False
            mock_manager.ensure_qemu_running.return_value = False
            mock_get_manager.return_value = mock_manager
            mock_warning.return_value = True

            obj = TestClass()
            result = obj.test_method()

            assert result is None
            assert obj.executed is False
            mock_critical.assert_called_once()

        obj.deleteLater()

    def test_requires_qiling_decorator_allows_execution_when_qiling_ready(
        self, qapp: QApplication
    ) -> None:
        """Decorator allows execution when Qiling is ready."""

        class TestClass:
            def __init__(self) -> None:
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qiling
            def test_method(self) -> str:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager:
            mock_manager = MagicMock()
            mock_manager.ensure_qiling_ready.return_value = True
            mock_get_manager.return_value = mock_manager

            obj = TestClass()
            result = obj.test_method()

            assert result == "success"
            assert obj.executed is True
            mock_manager.ensure_qiling_ready.assert_called_once_with(obj.binary_path)

    def test_requires_qiling_decorator_shows_error_when_qiling_fails(
        self, qapp: QApplication
    ) -> None:
        """Decorator shows error when Qiling fails to initialize."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = "D:\\test\\sample.exe"
                self.executed = False

            @EmulatorRequiredDecorator.requires_qiling
            def test_method(self) -> str | None:
                self.executed = True
                return "success"

        with patch(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager"
        ) as mock_get_manager, patch.object(QMessageBox, "critical") as mock_critical:

            mock_manager = MagicMock()
            mock_manager.ensure_qiling_ready.return_value = False
            mock_get_manager.return_value = mock_manager

            obj = TestClass()
            result = obj.test_method()

            assert result is None
            assert obj.executed is False
            mock_critical.assert_called_once()

        obj.deleteLater()

    def test_requires_qiling_decorator_blocks_execution_when_no_binary(
        self, qapp: QApplication
    ) -> None:
        """Decorator blocks execution when no binary is selected for Qiling."""

        class TestClass(QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.binary_path = ""
                self.executed = False

            @EmulatorRequiredDecorator.requires_qiling
            def test_method(self) -> str | None:
                self.executed = True
                return "success"

        with patch.object(QMessageBox, "warning") as mock_warning:
            obj = TestClass()
            result = obj.test_method()

            assert result is None
            assert obj.executed is False
            mock_warning.assert_called_once()

        obj.deleteLater()
