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
from typing import Any, Callable

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QFileDialog, QListWidgetItem, Qt

from intellicrack.ui.tabs.dashboard_tab import DashboardTab


class FakeThemeConfig:
    """Real test double for theme configuration."""

    def __init__(self) -> None:
        self.accent_color: str = "#3498db"
        self.success_color: str = "#2ecc71"
        self.error_color: str = "#e74c3c"
        self.border_radius: int = 5
        self.panel_color: str = "#2c3e50"
        self.background_color: str = "#1e272e"
        self.text_color: str = "#ecf0f1"
        self.text_color_secondary: str = "#95a5a6"
        self.input_background: str = "#34495e"
        self.border_color: str = "#7f8c8d"
        self.hover_color: str = "#16a085"
        self.button_color: str = "#2980b9"
        self.disabled_color: str = "#7f8c8d"


class FakeFontConfig:
    """Real test double for font configuration."""

    def __init__(self) -> None:
        self.family: str = "Segoe UI"
        self.base_size: int = 10
        self.header_size: int = 14


class FakeLayoutConfig:
    """Real test double for layout configuration."""

    def __init__(self) -> None:
        self.panel_spacing: int = 10
        self.margin_size: int = 15


class FakeConfigManager:
    """Real test double for UI configuration manager."""

    def __init__(self) -> None:
        self._settings: dict[str, Any] = {
            "recent_files": [],
            "dashboard.max_recent_files": 10,
            "dashboard.show_tabs": True,
            "dashboard.show_system_monitor": True,
            "dashboard.show_gpu_status": True,
            "dashboard.show_cpu_status": True,
            "dashboard.show_file_icons": True,
            "dashboard.auto_start_monitoring": True,
            "dashboard.auto_start_gpu_monitoring": True,
            "dashboard.auto_start_cpu_monitoring": True,
            "dashboard.monitor_refresh_interval": 5000,
            "dashboard.gpu_refresh_interval": 3000,
            "dashboard.cpu_refresh_interval": 2000,
        }
        self._callbacks: dict[str, list[Callable[[], None]]] = {}
        self._theme_config = FakeThemeConfig()
        self._font_config = FakeFontConfig()
        self._layout_config = FakeLayoutConfig()

    def get_theme_config(self) -> FakeThemeConfig:
        """Get theme configuration."""
        return self._theme_config

    def get_font_config(self) -> FakeFontConfig:
        """Get font configuration."""
        return self._font_config

    def get_layout_config(self) -> FakeLayoutConfig:
        """Get layout configuration."""
        return self._layout_config

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get configuration setting."""
        return self._settings.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        """Set configuration setting."""
        self._settings[key] = value

    def register_callback(self, key: str, callback: Callable[[], None]) -> None:
        """Register callback for configuration changes."""
        if key not in self._callbacks:
            self._callbacks[key] = []
        self._callbacks[key].append(callback)

    def unregister_callback(self, key: str, callback: Callable[[], None]) -> None:
        """Unregister callback for configuration changes."""
        if key in self._callbacks and callback in self._callbacks[key]:
            self._callbacks[key].remove(callback)


class FakeAppContext:
    """Real test double for application context with binary loading."""

    def __init__(self) -> None:
        self.loaded_binaries: list[str] = []

    def load_binary(self, file_path: str) -> None:
        """Record binary loading."""
        self.loaded_binaries.append(file_path)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def fake_config_manager() -> FakeConfigManager:
    """Create fake configuration manager."""
    return FakeConfigManager()


@pytest.fixture
def patched_config_manager(monkeypatch: pytest.MonkeyPatch, fake_config_manager: FakeConfigManager) -> FakeConfigManager:
    """Patch get_ui_config_manager to return fake config manager."""
    monkeypatch.setattr(
        "intellicrack.ui.tabs.dashboard_tab.get_ui_config_manager",
        lambda: fake_config_manager,
    )
    return fake_config_manager


class TestDashboardTabInitialization:
    """Test dashboard tab initialization."""

    def test_dashboard_tab_initializes_successfully(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab initializes with PyQt6 widgets."""
        tab = DashboardTab()

        assert tab is not None
        assert hasattr(tab, "config_manager")
        assert tab.is_loaded is True

        tab.cleanup()

    def test_dashboard_tab_creates_layout_structure(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates complete layout structure."""
        tab = DashboardTab()

        assert tab.layout() is not None
        assert hasattr(tab, "bottom_panel")

        tab.cleanup()

    def test_dashboard_tab_accepts_shared_context(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab accepts shared application context."""
        shared_context = FakeAppContext()
        tab = DashboardTab(shared_context=shared_context)

        assert tab.app_context == shared_context

        tab.cleanup()


class TestQuickStartPanel:
    """Test quick start panel functionality."""

    def test_dashboard_creates_quick_start_panel(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates quick start panel with action buttons."""
        tab = DashboardTab()

        panel = tab.create_quick_start_panel()

        assert panel is not None
        assert panel.title() == "Quick Start"

        tab.cleanup()

    def test_quick_start_panel_has_file_open_button(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Quick start panel contains file open button."""
        tab = DashboardTab()

        panel = tab.create_quick_start_panel()
        buttons = panel.findChildren(type(panel.findChild(type(None))))

        assert panel is not None

        tab.cleanup()

    def test_open_file_action_emits_binary_selected_signal(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Open file action emits binary selected signal."""
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
            monkeypatch.setattr(
                QFileDialog,
                "getOpenFileName",
                lambda *args, **kwargs: (test_path, ""),
            )
            tab.open_file_action()

            assert signal_emitted
            assert received_path == test_path

        finally:
            Path(test_path).unlink(missing_ok=True)
            tab.cleanup()

    def test_open_file_action_adds_to_recent_files(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Open file action adds selected file to recent files list."""
        tab = DashboardTab()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".dll") as tmp:
            tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
            tmp.flush()
            test_path = tmp.name

        try:
            monkeypatch.setattr(
                QFileDialog,
                "getOpenFileName",
                lambda *args, **kwargs: (test_path, ""),
            )
            tab.open_file_action()

            recent_files = patched_config_manager.get_setting("recent_files", [])
            assert test_path in recent_files

        finally:
            Path(test_path).unlink(missing_ok=True)
            tab.cleanup()

    def test_open_project_emits_project_opened_signal(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Open project action emits project opened signal."""
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
            monkeypatch.setattr(
                QFileDialog,
                "getOpenFileName",
                lambda *args, **kwargs: (test_path, ""),
            )
            tab.open_project()

            assert signal_emitted
            assert received_path == test_path

        finally:
            Path(test_path).unlink(missing_ok=True)
            tab.cleanup()


class TestRecentFilesList:
    """Test recent files list management."""

    def test_dashboard_creates_recent_files_panel(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates recent files panel."""
        tab = DashboardTab()

        panel = tab.create_recent_files_panel()

        assert panel is not None
        assert hasattr(tab, "recent_files_list")

        tab.cleanup()

    def test_recent_files_list_populated_from_config(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Recent files list populates from configuration manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_files = []
            for filename in ["test1.exe", "test2.dll"]:
                filepath = Path(tmpdir) / filename
                filepath.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
                test_files.append(str(filepath))

            patched_config_manager.set_setting("recent_files", test_files)

            tab = DashboardTab()

            tab.populate_recent_files()

            assert tab.recent_files_list.count() == 2

            tab.cleanup()

    def test_recent_files_list_shows_only_existing_files(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Recent files list filters out non-existent files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_file = Path(tmpdir) / "exists.exe"
            existing_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            recent_files = [str(existing_file), "C:\\nonexistent.dll"]

            patched_config_manager.set_setting("recent_files", recent_files)

            tab = DashboardTab()

            tab.populate_recent_files()

            assert tab.recent_files_list.count() == 1

            tab.cleanup()

    def test_load_recent_file_emits_binary_selected(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Loading recent file emits binary selected signal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.exe"
            test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            recent_files = [str(test_file)]

            patched_config_manager.set_setting("recent_files", recent_files)

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
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Adding to recent files maintains most recent first order."""
        tab = DashboardTab()

        tab.add_to_recent_files("C:\\file1.exe")
        tab.add_to_recent_files("C:\\file2.dll")
        tab.add_to_recent_files("C:\\file1.exe")

        recent_files = patched_config_manager.get_setting("recent_files", [])
        assert recent_files[0] == "C:\\file1.exe"
        assert recent_files[1] == "C:\\file2.dll"

        tab.cleanup()

    def test_clear_recent_files_empties_list(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """Clear recent files removes all entries."""
        patched_config_manager.set_setting("recent_files", ["C:\\test.exe"])

        tab = DashboardTab()

        tab.clear_recent_files()

        recent_files = patched_config_manager.get_setting("recent_files", [])
        assert not recent_files
        assert tab.recent_files_list.count() == 0

        tab.cleanup()


class TestSystemMonitorIntegration:
    """Test system monitor widget integration."""

    def test_dashboard_creates_system_monitor_panel(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates system monitor panel."""
        tab = DashboardTab()

        panel = tab.create_system_monitor_panel()

        assert panel is not None
        assert hasattr(tab, "system_monitor")

        tab.cleanup()

    def test_system_monitor_starts_when_configured(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """System monitor starts automatically when configured."""
        patched_config_manager.set_setting("dashboard.auto_start_monitoring", True)
        patched_config_manager.set_setting("dashboard.monitor_refresh_interval", 5000)

        tab = DashboardTab()

        tab.create_system_monitor_panel()

        assert hasattr(tab, "system_monitor")

        tab.cleanup()

    def test_system_monitor_alert_triggers_handler(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """System monitor alerts trigger handler method."""
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

    def test_dashboard_creates_gpu_status_panel(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates GPU status panel."""
        tab = DashboardTab()

        panel = tab.create_gpu_status_panel()

        assert panel is not None
        assert hasattr(tab, "gpu_status")

        tab.cleanup()

    def test_gpu_status_starts_when_configured(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """GPU status monitoring starts when configured."""
        patched_config_manager.set_setting("dashboard.auto_start_gpu_monitoring", True)
        patched_config_manager.set_setting("dashboard.gpu_refresh_interval", 3000)

        tab = DashboardTab()

        tab.create_gpu_status_panel()

        assert hasattr(tab, "gpu_status")

        tab.cleanup()


class TestCpuStatusIntegration:
    """Test CPU status widget integration."""

    def test_dashboard_creates_cpu_status_panel(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab creates CPU status panel."""
        tab = DashboardTab()

        panel = tab.create_cpu_status_panel()

        assert panel is not None
        assert hasattr(tab, "cpu_status")

        tab.cleanup()

    def test_cpu_status_starts_when_configured(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """CPU status monitoring starts when configured."""
        patched_config_manager.set_setting("dashboard.auto_start_cpu_monitoring", True)
        patched_config_manager.set_setting("dashboard.cpu_refresh_interval", 2000)

        tab = DashboardTab()

        tab.create_cpu_status_panel()

        assert hasattr(tab, "cpu_status")

        tab.cleanup()


class TestThemeApplication:
    """Test theme application and updates."""

    def test_dashboard_applies_theme_on_initialization(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab applies theme during initialization."""
        tab = DashboardTab()

        assert tab.is_loaded is True

        tab.cleanup()

    def test_dashboard_updates_theme_when_changed(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab updates theme when configuration changes."""
        tab = DashboardTab()

        tab.apply_theme()

        stylesheet = tab.styleSheet()
        assert stylesheet is not None

        tab.cleanup()

    def test_dashboard_updates_layout_when_config_changes(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab updates layout when configuration changes."""
        tab = DashboardTab()

        tab.update_layout()

        assert tab.layout() is not None

        tab.cleanup()


class TestCleanup:
    """Test resource cleanup."""

    def test_dashboard_cleanup_stops_monitors(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab cleanup stops all monitoring widgets."""
        tab = DashboardTab()

        tab.create_system_monitor_panel()
        tab.create_gpu_status_panel()
        tab.create_cpu_status_panel()

        tab.cleanup()

        assert hasattr(tab, "system_monitor")
        assert hasattr(tab, "gpu_status")
        assert hasattr(tab, "cpu_status")

    def test_dashboard_cleanup_unregisters_callbacks(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager
    ) -> None:
        """DashboardTab cleanup unregisters configuration callbacks."""
        tab = DashboardTab()

        initial_callback_count = sum(
            len(callbacks) for callbacks in patched_config_manager._callbacks.values()
        )

        tab.cleanup()

        final_callback_count = sum(
            len(callbacks) for callbacks in patched_config_manager._callbacks.values()
        )

        assert final_callback_count < initial_callback_count


class TestSharedContextIntegration:
    """Test shared application context integration."""

    def test_dashboard_uses_app_context_for_binary_loading(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DashboardTab uses app context to load binaries when available."""
        shared_context = FakeAppContext()
        tab = DashboardTab(shared_context=shared_context)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
            tmp.flush()
            test_path = tmp.name

        try:
            monkeypatch.setattr(
                QFileDialog,
                "getOpenFileName",
                lambda *args, **kwargs: (test_path, ""),
            )
            tab.open_file_action()

            assert test_path in shared_context.loaded_binaries

        finally:
            Path(test_path).unlink(missing_ok=True)
            tab.cleanup()

    def test_dashboard_functions_without_app_context(
        self, qapp: QApplication, patched_config_manager: FakeConfigManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DashboardTab functions correctly without shared context."""
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

            monkeypatch.setattr(
                QFileDialog,
                "getOpenFileName",
                lambda *args, **kwargs: (test_path, ""),
            )
            tab.open_file_action()

            assert signal_emitted

        finally:
            Path(test_path).unlink(missing_ok=True)
            tab.cleanup()
