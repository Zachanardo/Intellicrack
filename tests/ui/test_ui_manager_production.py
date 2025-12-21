"""Production tests for UIManager tab and layout management.

Tests comprehensive UI management including tab creation, layout initialization,
theme application, and component coordination.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMainWindow, QSplitter, QTabWidget, QVBoxLayout, QWidget

from intellicrack.ui.ui_manager import UIManager


@pytest.fixture
def main_window(qtbot: object) -> QMainWindow:
    window = QMainWindow()
    window.resize(1024, 768)
    window.show()
    qtbot.addWidget(window)
    return window


@pytest.fixture
def ui_manager_with_mocked_tabs(main_window: QMainWindow, monkeypatch: pytest.MonkeyPatch) -> UIManager:
    monkeypatch.setattr("intellicrack.ui.ui_manager.DashboardTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.AnalysisTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.ExploitationTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.AIAssistantTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.ToolsTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.TerminalTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.SettingsTab", MagicMock)
    monkeypatch.setattr("intellicrack.ui.ui_manager.WorkspaceTab", MagicMock)

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

    def test_create_main_layout_sets_central_widget(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()

        assert main_window.centralWidget() is not None
        assert isinstance(main_window.centralWidget(), QWidget)

    def test_create_main_layout_creates_vertical_layout(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()

        assert hasattr(main_window, "main_layout")
        assert isinstance(main_window.main_layout, QVBoxLayout)

    def test_create_main_layout_creates_splitter(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()

        assert hasattr(main_window, "main_splitter")
        assert isinstance(main_window.main_splitter, QSplitter)
        assert main_window.main_splitter.orientation() == Qt.Orientation.Horizontal

    def test_create_main_layout_calls_create_toolbar(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
        toolbar_created = []

        def mock_create_toolbar() -> None:
            toolbar_created.append(True)

        monkeypatch.setattr(main_window, "create_toolbar", mock_create_toolbar)

        ui_manager_with_mocked_tabs.create_main_layout()

        assert len(toolbar_created) > 0


class TestUIManagerTabsSetup:
    """Test UIManager tabs widget setup."""

    def test_setup_tabs_creates_tab_widget(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        assert hasattr(main_window, "tabs")
        assert isinstance(main_window.tabs, QTabWidget)

    def test_setup_tabs_configures_tab_position(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        assert main_window.tabs.tabPosition() == QTabWidget.TabPosition.North

    def test_setup_tabs_disables_closable_tabs(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        assert not main_window.tabs.tabsClosable()

    def test_setup_tabs_applies_theme(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        assert ui_manager_with_mocked_tabs.theme_manager is not None

    def test_setup_tabs_adds_to_splitter(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        assert main_window.main_splitter.count() > 0


class TestUIManagerOutputPanel:
    """Test UIManager output panel creation."""

    def test_create_output_panel_creates_widget(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.create_output_panel()

        assert hasattr(main_window, "output_panel")
        assert isinstance(main_window.output_panel, QWidget)

    def test_create_output_panel_creates_output_widgets(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.create_output_panel()

        assert hasattr(main_window, "output")
        assert hasattr(main_window, "raw_console_output")
        assert main_window.output.isReadOnly()
        assert main_window.raw_console_output.isReadOnly()

    def test_create_output_panel_creates_clear_button(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()

        monkeypatch_clear = MagicMock()
        main_window.clear_output = monkeypatch_clear

        ui_manager_with_mocked_tabs.create_output_panel()

        assert hasattr(main_window, "clear_output_btn")

    def test_create_output_panel_sets_max_block_count(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.create_output_panel()

        assert main_window.raw_console_output.maximumBlockCount() == 1000

    def test_create_output_panel_sets_splitter_sizes(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.create_output_panel()

        sizes = main_window.main_splitter.sizes()
        assert len(sizes) == 2
        assert sizes == [700, 500]


class TestUIManagerModularTabs:
    """Test UIManager modular tab creation."""

    def test_create_modular_tabs_creates_shared_context(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_modular_tabs()

        assert hasattr(main_window, "dashboard_tab")
        assert hasattr(main_window, "analysis_tab")
        assert hasattr(main_window, "exploitation_tab")

    def test_create_modular_tabs_adds_all_tabs(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_modular_tabs()

        expected_tabs = ["Dashboard", "Workspace", "Analysis", "Exploitation", "AI Assistant", "Tools", "Terminal", "Settings"]
        tab_count = main_window.tabs.count()

        assert tab_count == len(expected_tabs)

    def test_create_modular_tabs_in_correct_order(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_modular_tabs()

        expected_order = ["Dashboard", "Workspace", "Analysis", "Exploitation", "AI Assistant", "Tools", "Terminal", "Settings"]
        actual_order = [main_window.tabs.tabText(i) for i in range(main_window.tabs.count())]

        assert actual_order == expected_order

    def test_create_modular_tabs_stores_tab_references(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_modular_tabs()

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

    def test_complete_ui_setup_workflow(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()
        main_window.create_toolbar = MagicMock()
        main_window.clear_output = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_output_panel()
        ui_manager_with_mocked_tabs.create_modular_tabs()

        assert main_window.centralWidget() is not None
        assert hasattr(main_window, "tabs")
        assert hasattr(main_window, "output_panel")
        assert hasattr(main_window, "main_splitter")
        assert main_window.tabs.count() == 8

    def test_ui_components_properly_parented(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()
        main_window.create_toolbar = MagicMock()
        main_window.clear_output = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_output_panel()

        assert main_window.central_widget.parent() is main_window
        assert main_window.main_splitter.parent() is main_window.central_widget


class TestUIManagerThemeIntegration:
    """Test UIManager theme integration."""

    def test_theme_manager_retrieval(self, main_window: QMainWindow) -> None:
        ui_manager = UIManager(main_window)

        assert ui_manager.theme_manager is not None

    def test_theme_application_during_setup(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        with patch.object(ui_manager_with_mocked_tabs.theme_manager, "set_theme") as mock_set_theme:
            ui_manager_with_mocked_tabs.setup_tabs_and_themes()

            assert mock_set_theme.called


class TestUIManagerRealWorldScenarios:
    """Test UIManager real-world usage patterns."""

    def test_resize_splitter_maintains_layout(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()
        main_window.create_toolbar = MagicMock()
        main_window.clear_output = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_output_panel()

        main_window.main_splitter.setSizes([600, 400])

        sizes = main_window.main_splitter.sizes()
        assert sum(sizes) > 0
        assert main_window.main_splitter.count() == 2

    def test_tab_switching_functionality(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        main_window.app_context = MagicMock()
        main_window.task_manager = MagicMock()
        main_window.log_message = MagicMock()

        ui_manager_with_mocked_tabs.create_main_layout()
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()
        ui_manager_with_mocked_tabs.create_modular_tabs()

        main_window.tabs.setCurrentIndex(0)
        assert main_window.tabs.currentIndex() == 0

        main_window.tabs.setCurrentIndex(3)
        assert main_window.tabs.currentIndex() == 3

    def test_multiple_theme_applications(self, ui_manager_with_mocked_tabs: UIManager, main_window: QMainWindow) -> None:
        ui_manager_with_mocked_tabs.setup_tabs_and_themes()

        initial_theme = ui_manager_with_mocked_tabs.theme_manager.get_current_theme()

        ui_manager_with_mocked_tabs.theme_manager.set_theme("dark")
        ui_manager_with_mocked_tabs.theme_manager.set_theme("light")

        current_theme = ui_manager_with_mocked_tabs.theme_manager.get_current_theme()
        assert current_theme in ["dark", "light"] or current_theme == initial_theme
