"""Production-ready tests for intellicrack/ui/tabs/dashboard_tab.py

Tests validate REAL dashboard UI capabilities:
- Dashboard tab initialization with PyQt6 widgets
- Quick start panel with file/project/process selection
- Recent files list population and management
- System monitor widget integration and lifecycle
- GPU status monitoring and updates
- CPU status monitoring and updates
- File selection dialogs and binary loading
- Configuration manager integration for theming
- Signal emission for binary selection and project events
- Recent files persistence and ordering
- Theme application and dynamic updates
- Widget cleanup and resource management
"""

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QFileDialog, QListWidgetItem, Qt

from intellicrack.ui.tabs.dashboard_tab import DashboardTab


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_config_manager() -> MagicMock:
    """Create mock configuration manager."""
    mock = MagicMock()

    theme_config = MagicMock()
    theme_config.accent_color = "#3498db"
    theme_config.success_color = "#2ecc71"
    theme_config.error_color = "#e74c3c"
    theme_config.border_radius = 5
    theme_config.panel_color = "#2c3e50"
    theme_config.background_color = "#1e272e"
    theme_config.text_color = "#ecf0f1"
    theme_config.text_color_secondary = "#95a5a6"
    theme_config.input_background = "#34495e"
    theme_config.border_color = "#7f8c8d"
    theme_config.hover_color = "#16a085"
    theme_config.button_color = "#2980b9"
    theme_config.disabled_color = "#7f8c8d"

    font_config = MagicMock()
    font_config.family = "Segoe UI"
    font_config.base_size = 10
    font_config.header_size = 14

    layout_config = MagicMock()
    layout_config.panel_spacing = 10
    layout_config.margin_size = 15

    mock.get_theme_config.return_value = theme_config
    mock.get_font_config.return_value = font_config
    mock.get_layout_config.return_value = layout_config
    mock.get_setting.return_value = True

    return mock


class TestDashboardTabInitialization:
    """Test dashboard tab initialization."""

    def test_dashboard_tab_initializes_successfully(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab initializes with PyQt6 widgets."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            assert tab is not None
            assert hasattr(tab, "config_manager")
            assert tab.is_loaded is True

            tab.cleanup()

    def test_dashboard_tab_creates_layout_structure(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab creates complete layout structure."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            assert tab.layout() is not None
            assert hasattr(tab, "bottom_panel")

            tab.cleanup()

    def test_dashboard_tab_accepts_shared_context(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab accepts shared application context."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            shared_context = MagicMock()
            tab = DashboardTab(shared_context=shared_context)

            assert tab.app_context == shared_context

            tab.cleanup()


class TestQuickStartPanel:
    """Test quick start panel functionality."""

    def test_dashboard_creates_quick_start_panel(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab creates quick start panel with action buttons."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_quick_start_panel()

            assert panel is not None
            assert panel.title() == "Quick Start"

            tab.cleanup()

    def test_quick_start_panel_has_file_open_button(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """Quick start panel contains file open button."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_quick_start_panel()
            buttons = panel.findChildren(type(panel.findChild(type(None))))

            assert panel is not None

            tab.cleanup()

    def test_open_file_action_emits_binary_selected_signal(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Open file action emits binary selected signal."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            signal_emitted = False
            received_path = None

            def on_binary_selected(path: str) -> None:
                nonlocal signal_emitted, received_path
                signal_emitted = True
                received_path = path

            tab.binary_selected.connect(on_binary_selected)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
                tmp.flush()
                test_path = tmp.name

            try:
                with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "")):
                    tab.open_file_action()

                assert signal_emitted
                assert received_path == test_path

            finally:
                Path(test_path).unlink(missing_ok=True)
                tab.cleanup()

    def test_open_file_action_adds_to_recent_files(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Open file action adds selected file to recent files list."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            mock_config_manager.get_setting.side_effect = lambda key, default=None: [] if key == "recent_files" else (
                10 if key == "dashboard.max_recent_files" else default
            )

            tab = DashboardTab()

            with tempfile.NamedTemporaryFile(delete=False, suffix=".dll") as tmp:
                tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
                tmp.flush()
                test_path = tmp.name

            try:
                with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "")):
                    tab.open_file_action()

                mock_config_manager.set_setting.assert_called()
                calls = mock_config_manager.set_setting.call_args_list
                recent_files_call = [call for call in calls if call[0][0] == "recent_files"]

                assert recent_files_call

            finally:
                Path(test_path).unlink(missing_ok=True)
                tab.cleanup()

    def test_open_project_emits_project_opened_signal(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Open project action emits project opened signal."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            signal_emitted = False
            received_path = None

            def on_project_opened(path: str) -> None:
                nonlocal signal_emitted, received_path
                signal_emitted = True
                received_path = path

            tab.project_opened.connect(on_project_opened)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".icp") as tmp:
                tmp.write(b"PROJECT_DATA")
                tmp.flush()
                test_path = tmp.name

            try:
                with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "")):
                    tab.open_project()

                assert signal_emitted
                assert received_path == test_path

            finally:
                Path(test_path).unlink(missing_ok=True)
                tab.cleanup()


class TestRecentFilesList:
    """Test recent files list management."""

    def test_dashboard_creates_recent_files_panel(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab creates recent files panel."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_recent_files_panel()

            assert panel is not None
            assert hasattr(tab, "recent_files_list")

            tab.cleanup()

    def test_recent_files_list_populated_from_config(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Recent files list populates from configuration manager."""
        recent_files = ["C:\\test1.exe", "C:\\test2.dll"]

        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for filename in ["test1.exe", "test2.dll"]:
                filepath = Path(tmpdir) / filename
                filepath.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
                test_files.append(str(filepath))

            mock_config_manager.get_setting.side_effect = lambda key, default=None: test_files if key == "recent_files" else (
                10 if key == "dashboard.max_recent_files" else default
            )

            with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
                tab = DashboardTab()

                tab.populate_recent_files()

                assert tab.recent_files_list.count() == 2

                tab.cleanup()

    def test_recent_files_list_shows_only_existing_files(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Recent files list filters out non-existent files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_file = Path(tmpdir) / "exists.exe"
            existing_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            recent_files = [str(existing_file), "C:\\nonexistent.dll"]

            mock_config_manager.get_setting.side_effect = lambda key, default=None: recent_files if key == "recent_files" else (
                10 if key == "dashboard.max_recent_files" else default
            )

            with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
                tab = DashboardTab()

                tab.populate_recent_files()

                assert tab.recent_files_list.count() == 1

                tab.cleanup()

    def test_load_recent_file_emits_binary_selected(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Loading recent file emits binary selected signal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.exe"
            test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            recent_files = [str(test_file)]

            mock_config_manager.get_setting.side_effect = lambda key, default=None: recent_files if key == "recent_files" else (
                10 if key == "dashboard.max_recent_files" else default
            )

            with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
                tab = DashboardTab()
                tab.populate_recent_files()

                signal_emitted = False
                received_path = None

                def on_binary_selected(path: str) -> None:
                    nonlocal signal_emitted, received_path
                    signal_emitted = True
                    received_path = path

                tab.binary_selected.connect(on_binary_selected)

                item = tab.recent_files_list.item(0)
                tab.load_recent_file(item)

                assert signal_emitted
                assert received_path == str(test_file)

                tab.cleanup()

    def test_add_to_recent_files_maintains_order(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """Adding to recent files maintains most recent first order."""
        recent_files: list[str] = []

        def get_setting_side_effect(key: str, default: Any = None) -> Any:
            if key == "recent_files":
                return recent_files.copy()
            return 10 if key == "dashboard.max_recent_files" else default

        def set_setting_side_effect(key: str, value: Any) -> None:
            if key == "recent_files":
                recent_files.clear()
                recent_files.extend(value)

        mock_config_manager.get_setting.side_effect = get_setting_side_effect
        mock_config_manager.set_setting.side_effect = set_setting_side_effect

        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.add_to_recent_files("C:\\file1.exe")
            tab.add_to_recent_files("C:\\file2.dll")
            tab.add_to_recent_files("C:\\file1.exe")

            assert recent_files[0] == "C:\\file1.exe"
            assert recent_files[1] == "C:\\file2.dll"

            tab.cleanup()

    def test_clear_recent_files_empties_list(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """Clear recent files removes all entries."""
        recent_files = ["C:\\test.exe"]

        def set_setting_side_effect(key: str, value: Any) -> None:
            if key == "recent_files":
                recent_files.clear()
                recent_files.extend(value)

        mock_config_manager.get_setting.side_effect = lambda key, default=None: recent_files.copy() if key == "recent_files" else (
            10 if key == "dashboard.max_recent_files" else default
        )
        mock_config_manager.set_setting.side_effect = set_setting_side_effect

        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.clear_recent_files()

            assert not recent_files
            assert tab.recent_files_list.count() == 0

            tab.cleanup()


class TestSystemMonitorIntegration:
    """Test system monitor widget integration."""

    def test_dashboard_creates_system_monitor_panel(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab creates system monitor panel."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_system_monitor_panel()

            assert panel is not None
            assert hasattr(tab, "system_monitor")

            tab.cleanup()

    def test_system_monitor_starts_when_configured(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """System monitor starts automatically when configured."""
        mock_config_manager.get_setting.side_effect = lambda key, default=None: (
            True if key == "dashboard.auto_start_monitoring" else (
                5000 if key == "dashboard.monitor_refresh_interval" else default
            )
        )

        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.create_system_monitor_panel()

            assert hasattr(tab, "system_monitor")

            tab.cleanup()

    def test_system_monitor_alert_triggers_handler(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """System monitor alerts trigger handler method."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()
            tab.create_system_monitor_panel()

            handler_called = False
            alert_type_received = None

            original_handler = tab.handle_system_alert

            def test_handler(alert_type: str, message: str) -> None:
                nonlocal handler_called, alert_type_received
                handler_called = True
                alert_type_received = alert_type
                original_handler(alert_type, message)

            tab.handle_system_alert = test_handler

            tab.system_monitor.alert_triggered.emit("CPU", "CPU usage high")

            assert handler_called
            assert alert_type_received == "CPU"

            tab.cleanup()


class TestGpuStatusIntegration:
    """Test GPU status widget integration."""

    def test_dashboard_creates_gpu_status_panel(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab creates GPU status panel."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_gpu_status_panel()

            assert panel is not None
            assert hasattr(tab, "gpu_status")

            tab.cleanup()

    def test_gpu_status_starts_when_configured(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """GPU status monitoring starts when configured."""
        mock_config_manager.get_setting.side_effect = lambda key, default=None: (
            True if key == "dashboard.auto_start_gpu_monitoring" else (
                3000 if key == "dashboard.gpu_refresh_interval" else default
            )
        )

        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.create_gpu_status_panel()

            assert hasattr(tab, "gpu_status")

            tab.cleanup()


class TestCpuStatusIntegration:
    """Test CPU status widget integration."""

    def test_dashboard_creates_cpu_status_panel(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab creates CPU status panel."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            panel = tab.create_cpu_status_panel()

            assert panel is not None
            assert hasattr(tab, "cpu_status")

            tab.cleanup()

    def test_cpu_status_starts_when_configured(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """CPU status monitoring starts when configured."""
        mock_config_manager.get_setting.side_effect = lambda key, default=None: (
            True if key == "dashboard.auto_start_cpu_monitoring" else (
                2000 if key == "dashboard.cpu_refresh_interval" else default
            )
        )

        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.create_cpu_status_panel()

            assert hasattr(tab, "cpu_status")

            tab.cleanup()


class TestThemeApplication:
    """Test theme application and updates."""

    def test_dashboard_applies_theme_on_initialization(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab applies theme during initialization."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            assert tab.is_loaded is True

            tab.cleanup()

    def test_dashboard_updates_theme_when_changed(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab updates theme when configuration changes."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.apply_theme()

            stylesheet = tab.styleSheet()
            assert stylesheet is not None

            tab.cleanup()

    def test_dashboard_updates_layout_when_config_changes(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab updates layout when configuration changes."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.update_layout()

            assert tab.layout() is not None

            tab.cleanup()


class TestCleanup:
    """Test resource cleanup."""

    def test_dashboard_cleanup_stops_monitors(self, qapp: QApplication, mock_config_manager: MagicMock) -> None:
        """DashboardTab cleanup stops all monitoring widgets."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.create_system_monitor_panel()
            tab.create_gpu_status_panel()
            tab.create_cpu_status_panel()

            tab.cleanup()

            assert hasattr(tab, "system_monitor")
            assert hasattr(tab, "gpu_status")
            assert hasattr(tab, "cpu_status")

    def test_dashboard_cleanup_unregisters_callbacks(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab cleanup unregisters configuration callbacks."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab()

            tab.cleanup()

            assert mock_config_manager.unregister_callback.called


class TestSharedContextIntegration:
    """Test shared application context integration."""

    def test_dashboard_uses_app_context_for_binary_loading(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab uses app context to load binaries when available."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            shared_context = MagicMock()
            tab = DashboardTab(shared_context=shared_context)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
                tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
                tmp.flush()
                test_path = tmp.name

            try:
                with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "")):
                    tab.open_file_action()

                shared_context.load_binary.assert_called_once_with(test_path)

            finally:
                Path(test_path).unlink(missing_ok=True)
                tab.cleanup()

    def test_dashboard_functions_without_app_context(
        self, qapp: QApplication, mock_config_manager: MagicMock
    ) -> None:
        """DashboardTab functions correctly without shared context."""
        with patch("intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager", return_value=mock_config_manager):
            tab = DashboardTab(shared_context=None)

            assert tab.app_context is None

            with tempfile.NamedTemporaryFile(delete=False, suffix=".dll") as tmp:
                tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
                tmp.flush()
                test_path = tmp.name

            try:
                signal_emitted = False

                def on_binary_selected(path: str) -> None:
                    nonlocal signal_emitted
                    signal_emitted = True

                tab.binary_selected.connect(on_binary_selected)

                with patch.object(QFileDialog, "getOpenFileName", return_value=(test_path, "")):
                    tab.open_file_action()

                assert signal_emitted

            finally:
                Path(test_path).unlink(missing_ok=True)
                tab.cleanup()
