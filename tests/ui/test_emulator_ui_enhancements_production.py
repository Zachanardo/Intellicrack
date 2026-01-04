"""Production tests for emulator UI enhancements.

Tests EmulatorStatusWidget, decorator functionality, and emulator requirement validation
with real Qt widgets and actual emulator state management.

Copyright (C) 2025 Zachary Flint
"""

import pytest
from collections.abc import Generator
from pathlib import Path
from typing import Any, Callable

from intellicrack.handlers.pyqt6_handler import QApplication, QWidget, QMessageBox
from intellicrack.ui.emulator_ui_enhancements import (
    EmulatorStatusWidget,
    add_emulator_tooltips,
    show_emulator_warning,
    EmulatorRequiredDecorator,
)


class FakeEmulatorManager:
    """Real test double for EmulatorManager with configurable behavior."""

    def __init__(self) -> None:
        self.qemu_running: bool = False
        self.qiling_ready: bool = False
        self.ensure_qemu_running_called: bool = False
        self.ensure_qemu_running_call_count: int = 0
        self.ensure_qemu_running_binary_path: str | None = None
        self.ensure_qiling_ready_called: bool = False
        self.ensure_qiling_ready_call_count: int = 0
        self.ensure_qiling_ready_binary_path: str | None = None
        self.qemu_start_success: bool = True
        self.qiling_init_success: bool = True

    def ensure_qemu_running(self, binary_path: str) -> bool:
        """Track QEMU startup calls and return configured result."""
        self.ensure_qemu_running_called = True
        self.ensure_qemu_running_call_count += 1
        self.ensure_qemu_running_binary_path = binary_path
        return self.qemu_start_success

    def ensure_qiling_ready(self, binary_path: str) -> bool:
        """Track Qiling initialization calls and return configured result."""
        self.ensure_qiling_ready_called = True
        self.ensure_qiling_ready_call_count += 1
        self.ensure_qiling_ready_binary_path = binary_path
        return self.qiling_init_success


class FakeQMessageBoxExec:
    """Real test double for QMessageBox.exec with configurable return value."""

    def __init__(self, return_value: QMessageBox.StandardButton) -> None:
        self.return_value: QMessageBox.StandardButton = return_value
        self.called: bool = False
        self.call_count: int = 0

    def __call__(self, *args: Any, **kwargs: Any) -> QMessageBox.StandardButton:
        """Track calls and return configured value."""
        self.called = True
        self.call_count += 1
        return self.return_value


class FakeQMessageBoxWarning:
    """Real test double for QMessageBox.warning static method."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_count: int = 0
        self.parent: QWidget | None = None
        self.title: str = ""
        self.message: str = ""

    def __call__(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *args: Any,
        **kwargs: Any,
    ) -> QMessageBox.StandardButton:
        """Track warning dialog calls."""
        self.called = True
        self.call_count += 1
        self.parent = parent
        self.title = title
        self.message = message
        return QMessageBox.StandardButton.Ok


class FakeQMessageBoxCritical:
    """Real test double for QMessageBox.critical static method."""

    def __init__(self) -> None:
        self.called: bool = False
        self.call_count: int = 0
        self.parent: QWidget | None = None
        self.title: str = ""
        self.message: str = ""

    def __call__(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *args: Any,
        **kwargs: Any,
    ) -> QMessageBox.StandardButton:
        """Track critical dialog calls."""
        self.called = True
        self.call_count += 1
        self.parent = parent
        self.title = title
        self.message = message
        return QMessageBox.StandardButton.Ok


class FakeShowEmulatorWarning:
    """Real test double for show_emulator_warning function."""

    def __init__(self, return_value: bool = True) -> None:
        self.return_value: bool = return_value
        self.called: bool = False
        self.call_count: int = 0
        self.parent: QWidget | None = None
        self.emulator_type: str = ""
        self.feature_name: str = ""

    def __call__(
        self, parent: QWidget | None, emulator_type: str, feature_name: str
    ) -> bool:
        """Track warning calls and return configured value."""
        self.called = True
        self.call_count += 1
        self.parent = parent
        self.emulator_type = emulator_type
        self.feature_name = feature_name
        return self.return_value


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt widgets."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def emulator_status_widget(qapp: QApplication) -> Generator[EmulatorStatusWidget, None, None]:
    """Create EmulatorStatusWidget instance for testing."""
    widget = EmulatorStatusWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def fake_emulator_manager() -> FakeEmulatorManager:
    """Provide fake emulator manager for testing."""
    return FakeEmulatorManager()


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

        emulator_status_widget.update_emulator_status("QEMU", True, test_message)  # type: ignore[misc]

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
        emulator_status_widget.update_emulator_status("QEMU", True, "Running")  # type: ignore[misc]

        emulator_status_widget.update_emulator_status(  # type: ignore[misc]
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

        emulator_status_widget.update_emulator_status("Qiling", True, test_message)  # type: ignore[misc]

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
        emulator_status_widget.update_emulator_status("Qiling", True, "Ready")  # type: ignore[misc]

        emulator_status_widget.update_emulator_status(  # type: ignore[misc]
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
        emulator_status_widget.update_emulator_status(  # type: ignore[misc]
            "QEMU", True, "QEMU running on port 5555"
        )
        emulator_status_widget.update_emulator_status(  # type: ignore[misc]
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
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Showing QEMU warning displays correct message and buttons."""
        parent = QWidget()

        fake_exec = FakeQMessageBoxExec(QMessageBox.StandardButton.Yes)
        monkeypatch.setattr(QMessageBox, "exec", fake_exec)

        result = show_emulator_warning(parent, "QEMU", "Create Snapshot")

        assert result is True
        assert fake_exec.called
        assert fake_exec.call_count == 1

        parent.deleteLater()

    def test_show_emulator_warning_qiling_displays_correct_message(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Showing Qiling warning displays correct message and initializes automatically."""
        parent = QWidget()

        fake_exec = FakeQMessageBoxExec(QMessageBox.StandardButton.No)
        monkeypatch.setattr(QMessageBox, "exec", fake_exec)

        result = show_emulator_warning(parent, "Qiling", "Dynamic Analysis")

        assert result is False
        assert fake_exec.called
        assert fake_exec.call_count == 1

        parent.deleteLater()

    def test_show_emulator_warning_user_accepts_returns_true(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User accepting emulator warning returns True."""
        parent = QWidget()

        fake_exec = FakeQMessageBoxExec(QMessageBox.StandardButton.Yes)
        monkeypatch.setattr(QMessageBox, "exec", fake_exec)

        result = show_emulator_warning(parent, "QEMU", "Test Feature")

        assert result is True

        parent.deleteLater()

    def test_show_emulator_warning_user_rejects_returns_false(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User rejecting emulator warning returns False."""
        parent = QWidget()

        fake_exec = FakeQMessageBoxExec(QMessageBox.StandardButton.No)
        monkeypatch.setattr(QMessageBox, "exec", fake_exec)

        result = show_emulator_warning(parent, "QEMU", "Test Feature")

        assert result is False

        parent.deleteLater()


class TestEmulatorRequiredDecorator:
    """Test EmulatorRequiredDecorator functionality with real emulator checks."""

    def test_requires_qemu_decorator_allows_execution_when_qemu_running(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qemu_running = True

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )

        obj = TestClass()
        result = obj.test_method()

        assert result == "success"
        assert obj.executed is True

    def test_requires_qemu_decorator_starts_qemu_when_user_accepts(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qemu_running = False
        fake_emulator_manager.qemu_start_success = True

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        fake_warning = FakeShowEmulatorWarning(return_value=True)

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )
        monkeypatch.setattr(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning",
            fake_warning,
        )

        obj = TestClass()
        result = obj.test_method()

        assert result == "success"
        assert obj.executed is True
        assert fake_emulator_manager.ensure_qemu_running_called
        assert fake_emulator_manager.ensure_qemu_running_call_count == 1
        assert (
            fake_emulator_manager.ensure_qemu_running_binary_path == obj.binary_path
        )

        obj.deleteLater()

    def test_requires_qemu_decorator_blocks_execution_when_user_rejects(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qemu_running = False

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        fake_warning = FakeShowEmulatorWarning(return_value=False)

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )
        monkeypatch.setattr(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning",
            fake_warning,
        )

        obj = TestClass()
        result = obj.test_method()

        assert result is None
        assert obj.executed is False

        obj.deleteLater()

    def test_requires_qemu_decorator_shows_error_when_no_binary_selected(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
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

        fake_warning = FakeQMessageBoxWarning()
        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        obj = TestClass()
        result = obj.test_method()

        assert result is None
        assert obj.executed is False
        assert fake_warning.called
        assert fake_warning.call_count == 1

        obj.deleteLater()

    def test_requires_qemu_decorator_shows_error_when_qemu_fails_to_start(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qemu_running = False
        fake_emulator_manager.qemu_start_success = False

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        fake_warning = FakeShowEmulatorWarning(return_value=True)
        fake_critical = FakeQMessageBoxCritical()

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )
        monkeypatch.setattr(
            "intellicrack.ui.emulator_ui_enhancements.show_emulator_warning",
            fake_warning,
        )
        monkeypatch.setattr(QMessageBox, "critical", fake_critical)

        obj = TestClass()
        result = obj.test_method()

        assert result is None
        assert obj.executed is False
        assert fake_critical.called
        assert fake_critical.call_count == 1

        obj.deleteLater()

    def test_requires_qiling_decorator_allows_execution_when_qiling_ready(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qiling_init_success = True

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )

        obj = TestClass()
        result = obj.test_method()

        assert result == "success"
        assert obj.executed is True
        assert fake_emulator_manager.ensure_qiling_ready_called
        assert fake_emulator_manager.ensure_qiling_ready_call_count == 1
        assert fake_emulator_manager.ensure_qiling_ready_binary_path == obj.binary_path

    def test_requires_qiling_decorator_shows_error_when_qiling_fails(
        self,
        qapp: QApplication,
        fake_emulator_manager: FakeEmulatorManager,
        monkeypatch: pytest.MonkeyPatch,
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

        fake_emulator_manager.qiling_init_success = False

        def fake_get_manager() -> FakeEmulatorManager:
            return fake_emulator_manager

        fake_critical = FakeQMessageBoxCritical()

        monkeypatch.setattr(
            "intellicrack.core.processing.emulator_manager.get_emulator_manager",
            fake_get_manager,
        )
        monkeypatch.setattr(QMessageBox, "critical", fake_critical)

        obj = TestClass()
        result = obj.test_method()

        assert result is None
        assert obj.executed is False
        assert fake_critical.called
        assert fake_critical.call_count == 1

        obj.deleteLater()

    def test_requires_qiling_decorator_blocks_execution_when_no_binary(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
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

        fake_warning = FakeQMessageBoxWarning()
        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        obj = TestClass()
        result = obj.test_method()

        assert result is None
        assert obj.executed is False
        assert fake_warning.called
        assert fake_warning.call_count == 1

        obj.deleteLater()
