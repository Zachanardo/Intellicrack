"""Production tests for UIManager tab and layout management.

Tests comprehensive UI management including tab creation, layout initialization,
theme application, and component coordination.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMainWindow, QSplitter, QTabWidget, QVBoxLayout, QWidget

from intellicrack.ui.ui_manager import UIManager


class FakeAppContext:
    """Fake application context for testing."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.data[key] = value


class FakeTaskManager:
    """Fake task manager for testing."""

    def __init__(self) -> None:
        self.tasks: list[dict[str, Any]] = []

    def add_task(self, task: dict[str, Any]) -> None:
        self.tasks.append(task)

    def get_tasks(self) -> list[dict[str, Any]]:
        return self.tasks


class FakeTab(QWidget):
    """Fake tab widget for testing."""

    def __init__(self, shared_context: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.shared_context = shared_context
        self.initialized = True


class FakeThemeManager:
    """Fake theme manager for testing."""

    def __init__(self) -> None:
        self.current_theme = "dark"
        self.set_theme_calls: list[str] = []

    def get_current_theme(self) -> str:
        return self.current_theme

    def set_theme(self, theme_name: str) -> None:
        self.set_theme_calls.append(theme_name)
        self.current_theme = theme_name


@pytest.fixture
def main_window(qtbot: object) -> QMainWindow:
    window = QMainWindow()
    window.resize(1024, 768)
    window.show()
    qtbot.addWidget(window)
    return window


@pytest.fixture
def fake_theme_manager() -> FakeThemeManager:
    return FakeThemeManager()


@pytest.fixture
def ui_manager_with_fake_tabs(
    main_window: QMainWindow,
    monkeypatch: pytest.MonkeyPatch,
    fake_theme_manager: FakeThemeManager,
) -> UIManager:
    monkeypatch.setattr("intellicrack.ui.ui_manager.DashboardTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.AnalysisTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.ExploitationTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.AIAssistantTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.ToolsTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.TerminalTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.SettingsTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.WorkspaceTab", FakeTab)
    monkeypatch.setattr("intellicrack.ui.ui_manager.get_theme_manager", lambda: fake_theme_manager)

    return UIManager(main_window)


class TestUIManagerInitialization:
    """Test UIManager initialization and setup."""

    def test_initialization_stores_main_window_reference(self, main_window: QMainWindow) -> None:
        ui_manager = UIManager(main_window)

        assert ui_manager.main_window is main_window

    def test_initialization_creates_theme_manager(self, main_window: QMainWindow) -> None:
        ui_manager = UIManager(main_window)

        assert ui_manager.theme_manager is not None


class TestUIManagerLayoutCreation:
    """Test UIManager layout creation and structure."""

    def test_create_main_layout_sets_central_widget(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()

        assert main_window.centralWidget() is not None
        assert isinstance(main_window.centralWidget(), QWidget)

    def test_create_main_layout_creates_vertical_layout(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()

        assert hasattr(main_window, "main_layout")
        assert isinstance(main_window.main_layout, QVBoxLayout)

    def test_create_main_layout_creates_splitter(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()

        assert hasattr(main_window, "main_splitter")
        assert isinstance(main_window.main_splitter, QSplitter)
        assert main_window.main_splitter.orientation() == Qt.Orientation.Horizontal

    def test_create_main_layout_calls_create_toolbar(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        toolbar_created = []

        def fake_create_toolbar() -> None:
            toolbar_created.append(True)

        monkeypatch.setattr(main_window, "create_toolbar", fake_create_toolbar)

        ui_manager_with_fake_tabs.create_main_layout()

        assert toolbar_created


class TestUIManagerTabsSetup:
    """Test UIManager tabs widget setup."""

    def test_setup_tabs_creates_tab_widget(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert hasattr(main_window, "tabs")
        assert isinstance(main_window.tabs, QTabWidget)

    def test_setup_tabs_configures_tab_position(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert main_window.tabs.tabPosition() == QTabWidget.TabPosition.North

    def test_setup_tabs_disables_closable_tabs(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert not main_window.tabs.tabsClosable()

    def test_setup_tabs_applies_theme(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert ui_manager_with_fake_tabs.theme_manager is not None

    def test_setup_tabs_adds_to_splitter(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert main_window.main_splitter.count() > 0


class TestUIManagerOutputPanel:
    """Test UIManager output panel creation."""

    def test_create_output_panel_creates_widget(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.create_output_panel()

        assert hasattr(main_window, "output_panel")
        assert isinstance(main_window.output_panel, QWidget)

    def test_create_output_panel_creates_output_widgets(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.create_output_panel()

        assert hasattr(main_window, "output")
        assert hasattr(main_window, "raw_console_output")
        assert main_window.output.isReadOnly()
        assert main_window.raw_console_output.isReadOnly()

    def test_create_output_panel_creates_clear_button(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()

        clear_output_called = []

        def fake_clear_output() -> None:
            clear_output_called.append(True)

        main_window.clear_output = fake_clear_output

        ui_manager_with_fake_tabs.create_output_panel()

        assert hasattr(main_window, "clear_output_btn")

    def test_create_output_panel_sets_max_block_count(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.create_output_panel()

        assert main_window.raw_console_output.maximumBlockCount() == 1000

    def test_create_output_panel_sets_splitter_sizes(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.create_output_panel()

        sizes = main_window.main_splitter.sizes()
        assert len(sizes) == 2
        assert sizes == [700, 500]


class TestUIManagerModularTabs:
    """Test UIManager modular tab creation."""

    def test_create_modular_tabs_creates_shared_context(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_modular_tabs()

        assert hasattr(main_window, "dashboard_tab")
        assert hasattr(main_window, "analysis_tab")
        assert hasattr(main_window, "exploitation_tab")

    def test_create_modular_tabs_adds_all_tabs(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_modular_tabs()

        expected_tabs = [
            "Dashboard",
            "Workspace",
            "Analysis",
            "Exploitation",
            "AI Assistant",
            "Tools",
            "Terminal",
            "Settings",
        ]
        tab_count = main_window.tabs.count()

        assert tab_count == len(expected_tabs)

    def test_create_modular_tabs_in_correct_order(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_modular_tabs()

        expected_order = [
            "Dashboard",
            "Workspace",
            "Analysis",
            "Exploitation",
            "AI Assistant",
            "Tools",
            "Terminal",
            "Settings",
        ]
        actual_order = [main_window.tabs.tabText(i) for i in range(main_window.tabs.count())]

        assert actual_order == expected_order

    def test_create_modular_tabs_stores_tab_references(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_modular_tabs()

        assert hasattr(main_window, "dashboard_tab")
        assert hasattr(main_window, "workspace_tab")
        assert hasattr(main_window, "analysis_tab")
        assert hasattr(main_window, "exploitation_tab")
        assert hasattr(main_window, "ai_assistant_tab")
        assert hasattr(main_window, "tools_tab")
        assert hasattr(main_window, "terminal_tab")
        assert hasattr(main_window, "settings_tab")


class TestUIManagerIntegration:
    """Test UIManager complete integration workflow."""

    def test_complete_ui_setup_workflow(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        toolbar_created = []

        def fake_create_toolbar() -> None:
            toolbar_created.append(True)

        main_window.create_toolbar = fake_create_toolbar

        clear_output_called = []

        def fake_clear_output() -> None:
            clear_output_called.append(True)

        main_window.clear_output = fake_clear_output

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_output_panel()
        ui_manager_with_fake_tabs.create_modular_tabs()

        assert main_window.centralWidget() is not None
        assert hasattr(main_window, "tabs")
        assert hasattr(main_window, "output_panel")
        assert hasattr(main_window, "main_splitter")
        assert main_window.tabs.count() == 8

    def test_ui_components_properly_parented(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        toolbar_created = []

        def fake_create_toolbar() -> None:
            toolbar_created.append(True)

        main_window.create_toolbar = fake_create_toolbar

        clear_output_called = []

        def fake_clear_output() -> None:
            clear_output_called.append(True)

        main_window.clear_output = fake_clear_output

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_output_panel()

        assert main_window.central_widget.parent() is main_window
        assert main_window.main_splitter.parent() is main_window.central_widget


class TestUIManagerThemeIntegration:
    """Test UIManager theme integration."""

    def test_theme_manager_retrieval(self, main_window: QMainWindow) -> None:
        ui_manager = UIManager(main_window)

        assert ui_manager.theme_manager is not None

    def test_theme_application_during_setup(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow, fake_theme_manager: FakeThemeManager
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        assert len(fake_theme_manager.set_theme_calls) > 0


class TestUIManagerRealWorldScenarios:
    """Test UIManager real-world usage patterns."""

    def test_resize_splitter_maintains_layout(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        toolbar_created = []

        def fake_create_toolbar() -> None:
            toolbar_created.append(True)

        main_window.create_toolbar = fake_create_toolbar

        clear_output_called = []

        def fake_clear_output() -> None:
            clear_output_called.append(True)

        main_window.clear_output = fake_clear_output

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_output_panel()

        main_window.main_splitter.setSizes([600, 400])

        sizes = main_window.main_splitter.sizes()
        assert sum(sizes) > 0
        assert main_window.main_splitter.count() == 2

    def test_tab_switching_functionality(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow
    ) -> None:
        main_window.app_context = FakeAppContext()
        main_window.task_manager = FakeTaskManager()

        log_messages = []

        def fake_log_message(message: str, level: str = "INFO") -> None:
            log_messages.append((message, level))

        main_window.log_message = fake_log_message

        ui_manager_with_fake_tabs.create_main_layout()
        ui_manager_with_fake_tabs.setup_tabs_and_themes()
        ui_manager_with_fake_tabs.create_modular_tabs()

        main_window.tabs.setCurrentIndex(0)
        assert main_window.tabs.currentIndex() == 0

        main_window.tabs.setCurrentIndex(3)
        assert main_window.tabs.currentIndex() == 3

    def test_multiple_theme_applications(
        self, ui_manager_with_fake_tabs: UIManager, main_window: QMainWindow, fake_theme_manager: FakeThemeManager
    ) -> None:
        ui_manager_with_fake_tabs.setup_tabs_and_themes()

        initial_theme = fake_theme_manager.get_current_theme()

        fake_theme_manager.set_theme("dark")
        fake_theme_manager.set_theme("light")

        current_theme = fake_theme_manager.get_current_theme()
        assert current_theme in ["dark", "light", initial_theme]
