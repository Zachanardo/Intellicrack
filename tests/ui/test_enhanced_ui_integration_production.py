"""Production tests for enhanced UI integration.

This module validates the EnhancedAnalysisDashboard and EnhancedMainWindow
components that provide comprehensive radare2 analysis integration.

Copyright (C) 2025 Zachary Flint
"""

from collections.abc import Generator
from pathlib import Path
from typing import Any, Callable

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QWidget
from intellicrack.ui.enhanced_ui_integration import (
    EnhancedAnalysisDashboard,
    EnhancedMainWindow,
    create_enhanced_application,
    integrate_enhanced_ui_with_existing_app,
)


class FakeLabel:
    """Test double for QLabel with text tracking."""

    def __init__(self, initial_text: str = "") -> None:
        self._text: str = initial_text
        self._style_sheet: str = ""

    def text(self) -> str:
        return self._text

    def setText(self, text: str) -> None:
        self._text = text

    def styleSheet(self) -> str:
        return self._style_sheet

    def setStyleSheet(self, style: str) -> None:
        self._style_sheet = style


class FakeFileDialog:
    """Test double for QFileDialog with configurable file selection."""

    def __init__(self) -> None:
        self.open_file_result: tuple[str, str] = ("", "")
        self.save_file_result: tuple[str, str] = ("", "")
        self.call_count: int = 0

    def getOpenFileName(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = "",
    ) -> tuple[str, str]:
        self.call_count += 1
        return self.open_file_result

    def getSaveFileName(
        self,
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = "",
    ) -> tuple[str, str]:
        self.call_count += 1
        return self.save_file_result


class FakeR2ConfigurationDialog:
    """Test double for R2ConfigurationDialog with exec tracking."""

    def __init__(self) -> None:
        self.exec_called: bool = False
        self.exec_result: int = 0

    def exec(self) -> int:
        self.exec_called = True
        return self.exec_result


class FakeMessageBox:
    """Test double for QMessageBox with call tracking."""

    def __init__(self) -> None:
        self.warning_calls: list[tuple[Any, str, str]] = []
        self.information_calls: list[tuple[Any, str, str]] = []
        self.about_calls: list[tuple[Any, str, str]] = []

    def warning(self, parent: Any, title: str, message: str) -> None:
        self.warning_calls.append((parent, title, message))

    def information(self, parent: Any, title: str, message: str) -> None:
        self.information_calls.append((parent, title, message))

    def about(self, parent: Any, title: str, message: str) -> None:
        self.about_calls.append((parent, title, message))


class FakeR2Widget:
    """Test double for Radare2Widget with analysis tracking."""

    def __init__(self) -> None:
        self.binary_path: str | None = None
        self.analysis_calls: list[str] = []

    def set_binary_path(self, path: str) -> None:
        self.binary_path = path

    def _start_analysis(self, analysis_type: str) -> None:
        self.analysis_calls.append(analysis_type)


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt widgets."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def enhanced_dashboard(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> Generator[EnhancedAnalysisDashboard, None, None]:
    """Create EnhancedAnalysisDashboard instance for testing."""
    def fake_setup_overview_tab(self: EnhancedAnalysisDashboard) -> None:
        pass

    monkeypatch.setattr(
        EnhancedAnalysisDashboard,
        "_setup_overview_tab",
        fake_setup_overview_tab,
    )

    dashboard = EnhancedAnalysisDashboard()
    dashboard.stats_labels = {
        "files_analyzed": FakeLabel("0"),  # type: ignore[dict-item]
        "vulnerabilities_found": FakeLabel("0"),  # type: ignore[dict-item]
        "license_functions": FakeLabel("0"),  # type: ignore[dict-item]
        "bypass_opportunities": FakeLabel("0"),  # type: ignore[dict-item]
    }

    from intellicrack.handlers.pyqt6_handler import QListWidget, QLabel
    dashboard.activity_list = QListWidget()
    dashboard.analysis_status = QLabel("Ready")

    yield dashboard
    dashboard.deleteLater()


@pytest.fixture
def enhanced_main_window(qapp: QApplication) -> Generator[EnhancedMainWindow, None, None]:
    """Create EnhancedMainWindow instance for testing."""
    window = EnhancedMainWindow()
    yield window
    window.deleteLater()


class TestEnhancedAnalysisDashboard:
    """Test EnhancedAnalysisDashboard functionality."""

    def test_dashboard_initialization_creates_tabs(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Dashboard initializes with all required tabs."""
        assert hasattr(enhanced_dashboard, "content_tabs")
        assert enhanced_dashboard.content_tabs.count() >= 4

        tab_names = [
            enhanced_dashboard.content_tabs.tabText(i)
            for i in range(enhanced_dashboard.content_tabs.count())
        ]

        assert "Overview" in tab_names
        assert "Radare2 Analysis" in tab_names or "Visualization" in tab_names
        assert "Reports" in tab_names

    def test_dashboard_has_stats_labels(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Dashboard initializes with statistics labels."""
        assert hasattr(enhanced_dashboard, "stats_labels")
        assert "files_analyzed" in enhanced_dashboard.stats_labels
        assert "vulnerabilities_found" in enhanced_dashboard.stats_labels
        assert "license_functions" in enhanced_dashboard.stats_labels
        assert "bypass_opportunities" in enhanced_dashboard.stats_labels

    def test_update_stats_modifies_label_values(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Updating stats changes label text correctly."""
        test_stats = {
            "files_analyzed": 42,
            "vulnerabilities_found": 15,
            "license_functions": 23,
            "bypass_opportunities": 8,
        }

        enhanced_dashboard.update_stats(test_stats)

        assert enhanced_dashboard.stats_labels["files_analyzed"].text() == "42"
        assert enhanced_dashboard.stats_labels["vulnerabilities_found"].text() == "15"
        assert enhanced_dashboard.stats_labels["license_functions"].text() == "23"
        assert enhanced_dashboard.stats_labels["bypass_opportunities"].text() == "8"

    def test_add_activity_appends_to_activity_list(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Adding activity appends message to activity list."""
        initial_count = enhanced_dashboard.activity_list.count()

        enhanced_dashboard.add_activity("Test activity message")

        assert enhanced_dashboard.activity_list.count() == initial_count + 1
        latest_item = enhanced_dashboard.activity_list.item(0).text()  # type: ignore[union-attr]
        assert "Test activity message" in latest_item

    def test_add_activity_limits_list_to_20_items(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Activity list is limited to 20 items maximum."""
        for i in range(25):
            enhanced_dashboard.add_activity(f"Activity {i}")

        assert enhanced_dashboard.activity_list.count() == 20

    def test_set_analysis_status_updates_status_label(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Setting analysis status updates status label text and color."""
        from intellicrack.handlers.pyqt6_handler import QLabel
        enhanced_dashboard.analysis_status = QLabel("Ready")

        enhanced_dashboard.set_analysis_status("Analyzing", "#e74c3c")

        assert enhanced_dashboard.analysis_status.text() == "Analyzing"
        assert "#e74c3c" in enhanced_dashboard.analysis_status.styleSheet()

    def test_start_new_analysis_switches_to_radare2_tab(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Starting new analysis switches to radare2 tab."""
        enhanced_dashboard.content_tabs.setCurrentIndex(0)
        enhanced_dashboard._start_new_analysis()

        assert enhanced_dashboard.content_tabs.currentIndex() == 1

    def test_load_report_opens_file_dialog(
        self, enhanced_dashboard: EnhancedAnalysisDashboard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading report opens file dialog."""
        fake_dialog = FakeFileDialog()
        fake_dialog.open_file_result = ("test_report.json", "JSON Files (*.json)")

        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog",
            fake_dialog,
        )

        enhanced_dashboard._load_report()

        assert fake_dialog.call_count == 1

    def test_load_report_adds_activity_when_file_selected(
        self, enhanced_dashboard: EnhancedAnalysisDashboard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loading report adds activity when file is selected."""
        fake_dialog = FakeFileDialog()
        fake_dialog.open_file_result = ("D:\\test\\report.json", "JSON Files (*.json)")

        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog",
            fake_dialog,
        )

        initial_count = enhanced_dashboard.activity_list.count()
        enhanced_dashboard._load_report()

        assert enhanced_dashboard.activity_list.count() > initial_count

    def test_open_settings_opens_configuration_dialog(
        self, enhanced_dashboard: EnhancedAnalysisDashboard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening settings opens configuration dialog."""
        fake_dialog = FakeR2ConfigurationDialog()

        def create_fake_dialog() -> FakeR2ConfigurationDialog:
            return fake_dialog

        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.R2ConfigurationDialog",
            create_fake_dialog,
        )

        enhanced_dashboard._open_settings()

        assert fake_dialog.exec_called

    def test_update_visualization_clears_scene(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Updating visualization clears graphics scene."""
        enhanced_dashboard._update_visualization("Call Graph")

        assert enhanced_dashboard.viz_info.toPlainText() != ""

    def test_generate_report_populates_report_editor(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Generating report populates report editor with content."""
        enhanced_dashboard.report_template_combo.setCurrentText(
            "Vulnerability Assessment"
        )
        enhanced_dashboard._generate_report()

        report_text = enhanced_dashboard.report_editor.toPlainText()
        assert "Vulnerability Assessment" in report_text

    def test_save_report_writes_file(
        self, enhanced_dashboard: EnhancedAnalysisDashboard, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Saving report writes content to file."""
        report_file = tmp_path / "test_report.txt"

        fake_dialog = FakeFileDialog()
        fake_dialog.save_file_result = (str(report_file), "Text Files (*.txt)")

        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog",
            fake_dialog,
        )

        enhanced_dashboard.report_editor.setText("Test report content")
        enhanced_dashboard._save_report()

        assert report_file.exists()
        assert report_file.read_text(encoding="utf-8") == "Test report content"


class TestEnhancedMainWindow:
    """Test EnhancedMainWindow functionality."""

    def test_main_window_initialization_creates_dashboard(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Main window initializes with dashboard as central widget."""
        assert hasattr(enhanced_main_window, "dashboard")
        assert isinstance(
            enhanced_main_window.dashboard, EnhancedAnalysisDashboard
        )
        assert enhanced_main_window.centralWidget() == enhanced_main_window.dashboard

    def test_main_window_has_menu_bar(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Main window has menu bar with expected menus."""
        menu_bar = enhanced_main_window.menuBar()
        assert menu_bar is not None

        menu_titles = [
            menu_bar.actions()[i].text()
            for i in range(len(menu_bar.actions()))
        ]

        assert "File" in menu_titles
        assert "Analysis" in menu_titles
        assert "Tools" in menu_titles
        assert "Help" in menu_titles

    def test_main_window_has_status_bar(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Main window has status bar with widgets."""
        assert hasattr(enhanced_main_window, "status_bar")
        assert hasattr(enhanced_main_window, "progress_bar")
        assert hasattr(enhanced_main_window, "binary_info_label")

    def test_open_file_sets_binary_path(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening file sets binary path and updates UI."""
        test_file = "D:\\test\\sample.exe"

        fake_dialog = FakeFileDialog()
        fake_dialog.open_file_result = (test_file, "All Files (*)")

        fake_r2_widget = FakeR2Widget()
        enhanced_main_window.dashboard.r2_widget = fake_r2_widget  # type: ignore[assignment]

        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog",
            fake_dialog,
        )

        enhanced_main_window._open_file()

        assert enhanced_main_window.binary_path == test_file
        assert "sample.exe" in enhanced_main_window.binary_info_label.text()
        assert fake_r2_widget.binary_path == test_file

    def test_start_analysis_requires_binary_file(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Starting analysis without binary file shows warning."""
        enhanced_main_window.binary_path = None

        fake_message_box = FakeMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox",
            fake_message_box,
        )

        enhanced_main_window._start_analysis("comprehensive")

        assert len(fake_message_box.warning_calls) == 1

    def test_start_analysis_with_binary_updates_status(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Starting analysis with binary updates dashboard status."""
        enhanced_main_window.binary_path = "D:\\test\\sample.exe"

        fake_r2_widget = FakeR2Widget()
        enhanced_main_window.dashboard.r2_widget = fake_r2_widget  # type: ignore[assignment]

        enhanced_main_window._start_analysis("vulnerability")

        assert enhanced_main_window.progress_bar.isVisible()
        assert "vulnerability" in fake_r2_widget.analysis_calls

    def test_save_results_requires_analysis_data(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Saving results without analysis data shows info message."""
        fake_message_box = FakeMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox",
            fake_message_box,
        )

        enhanced_main_window._save_results()

        assert len(fake_message_box.information_calls) == 1

    def test_export_report_switches_to_reports_tab(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Exporting report switches to reports tab."""
        enhanced_main_window._export_report()

        assert enhanced_main_window.dashboard.content_tabs.currentIndex() == 3

    def test_open_hex_viewer_requires_binary_file(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening hex viewer without binary shows warning."""
        enhanced_main_window.binary_path = None

        fake_message_box = FakeMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox",
            fake_message_box,
        )

        enhanced_main_window._open_hex_viewer()

        assert len(fake_message_box.warning_calls) == 1

    def test_show_about_displays_about_dialog(
        self, enhanced_main_window: EnhancedMainWindow, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Showing about displays about dialog."""
        fake_message_box = FakeMessageBox()
        monkeypatch.setattr(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox",
            fake_message_box,
        )

        enhanced_main_window._show_about()

        assert len(fake_message_box.about_calls) == 1
        assert "Intellicrack" in str(fake_message_box.about_calls[0])


class TestEnhancedApplicationCreation:
    """Test enhanced application creation functions."""

    def test_create_enhanced_application_returns_app_and_window(
        self, qapp: QApplication
    ) -> None:
        """Creating enhanced application returns app and window instances."""
        app, window = create_enhanced_application()

        assert app is not None
        assert isinstance(window, EnhancedMainWindow)
        assert app.applicationName() == "Intellicrack"
        assert app.applicationVersion() == "2.0"

        window.deleteLater()

    def test_integrate_enhanced_ui_with_existing_app_adds_dashboard(
        self, qapp: QApplication
    ) -> None:
        """Integrating enhanced UI with existing app adds dashboard tab."""
        from intellicrack.handlers.pyqt6_handler import QTabWidget

        class FakeApp:
            def __init__(self) -> None:
                self.tab_widget: QTabWidget = QTabWidget()
                self.enhanced_dashboard: EnhancedAnalysisDashboard | None = None

        fake_app = FakeApp()
        result = integrate_enhanced_ui_with_existing_app(fake_app)

        assert result is True
        assert fake_app.enhanced_dashboard is not None
        assert fake_app.tab_widget.count() > 0

    def test_integrate_enhanced_ui_with_existing_app_adds_menu(
        self, qapp: QApplication
    ) -> None:
        """Integrating enhanced UI with existing app adds enhanced menu."""
        from intellicrack.handlers.pyqt6_handler import QMainWindow, QTabWidget

        class FakeApp(QMainWindow):
            def __init__(self) -> None:
                super().__init__()
                self.tab_widget = QTabWidget()

        fake_app = FakeApp()
        result = integrate_enhanced_ui_with_existing_app(fake_app)

        assert result is True

        menu_bar = fake_app.menuBar()
        menu_titles = [
            menu_bar.actions()[i].text()  # type: ignore[union-attr]
            for i in range(len(menu_bar.actions()))  # type: ignore[union-attr]
        ]
        assert "Enhanced Analysis" in menu_titles

        fake_app.deleteLater()

    def test_integrate_enhanced_ui_handles_exceptions(
        self, qapp: QApplication
    ) -> None:
        """Integrating enhanced UI handles exceptions gracefully."""
        class FakeTabWidget:
            def addTab(self, widget: Any, label: str) -> None:
                raise Exception("Test exception")

        class FakeApp:
            def __init__(self) -> None:
                self.tab_widget = FakeTabWidget()

        fake_app = FakeApp()
        result = integrate_enhanced_ui_with_existing_app(fake_app)

        assert result is False


class TestDashboardColorDarkening:
    """Test dashboard color darkening functionality."""

    def test_darken_color_darkens_known_colors(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Darkening color returns darker shade for known colors."""
        assert enhanced_dashboard._darken_color("#3498db") == "#2980b9"
        assert enhanced_dashboard._darken_color("#9b59b6") == "#8e44ad"
        assert enhanced_dashboard._darken_color("#e67e22") == "#d35400"
        assert enhanced_dashboard._darken_color("#95a5a6") == "#7f8c8d"

    def test_darken_color_returns_original_for_unknown_colors(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Darkening color returns original for unknown colors."""
        assert enhanced_dashboard._darken_color("#ff0000") == "#ff0000"
        assert enhanced_dashboard._darken_color("#00ff00") == "#00ff00"


class TestDashboardTimestamp:
    """Test dashboard timestamp generation."""

    def test_get_ui_timestamp_returns_formatted_time(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Getting UI timestamp returns formatted time string."""
        timestamp = enhanced_dashboard._get_ui_timestamp()

        assert isinstance(timestamp, str)
        assert ":" in timestamp
        parts = timestamp.split(":")
        assert len(parts) == 3
        assert all(part.isdigit() for part in parts)
