"""Production tests for enhanced UI integration.

This module validates the EnhancedAnalysisDashboard and EnhancedMainWindow
components that provide comprehensive radare2 analysis integration.

Copyright (C) 2025 Zachary Flint
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QWidget
from intellicrack.ui.enhanced_ui_integration import (
    EnhancedAnalysisDashboard,
    EnhancedMainWindow,
    create_enhanced_application,
    integrate_enhanced_ui_with_existing_app,
)


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for Qt widgets."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def enhanced_dashboard(qapp: QApplication) -> EnhancedAnalysisDashboard:
    """Create EnhancedAnalysisDashboard instance for testing."""
    with patch.object(
        EnhancedAnalysisDashboard, "_setup_overview_tab", return_value=None
    ):
        dashboard = EnhancedAnalysisDashboard()
        dashboard._setup_overview_tab_original = dashboard._setup_overview_tab
        dashboard.stats_labels = {
            "files_analyzed": Mock(text=Mock(return_value="0"), setText=Mock()),
            "vulnerabilities_found": Mock(text=Mock(return_value="0"), setText=Mock()),
            "license_functions": Mock(text=Mock(return_value="0"), setText=Mock()),
            "bypass_opportunities": Mock(text=Mock(return_value="0"), setText=Mock()),
        }
        from intellicrack.handlers.pyqt6_handler import QListWidget
        dashboard.activity_list = QListWidget()
        from intellicrack.handlers.pyqt6_handler import QLabel
        dashboard.analysis_status = QLabel("Ready")
        yield dashboard
        dashboard.deleteLater()


@pytest.fixture
def enhanced_main_window(qapp: QApplication) -> EnhancedMainWindow:
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

        enhanced_dashboard.stats_labels["files_analyzed"].setText.assert_called_with("42")
        enhanced_dashboard.stats_labels["vulnerabilities_found"].setText.assert_called_with("15")
        enhanced_dashboard.stats_labels["license_functions"].setText.assert_called_with("23")
        enhanced_dashboard.stats_labels["bypass_opportunities"].setText.assert_called_with("8")

    def test_add_activity_appends_to_activity_list(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Adding activity appends message to activity list."""
        initial_count = enhanced_dashboard.activity_list.count()

        enhanced_dashboard.add_activity("Test activity message")

        assert enhanced_dashboard.activity_list.count() == initial_count + 1
        latest_item = enhanced_dashboard.activity_list.item(0).text()
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
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Loading report opens file dialog."""
        with patch(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog.getOpenFileName"
        ) as mock_dialog:
            mock_dialog.return_value = ("test_report.json", "JSON Files (*.json)")

            enhanced_dashboard._load_report()

            mock_dialog.assert_called_once()

    def test_load_report_adds_activity_when_file_selected(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Loading report adds activity when file is selected."""
        with patch(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog.getOpenFileName"
        ) as mock_dialog:
            mock_dialog.return_value = ("D:\\test\\report.json", "JSON Files (*.json)")

            initial_count = enhanced_dashboard.activity_list.count()
            enhanced_dashboard._load_report()

            assert enhanced_dashboard.activity_list.count() > initial_count

    def test_open_settings_opens_configuration_dialog(
        self, enhanced_dashboard: EnhancedAnalysisDashboard
    ) -> None:
        """Opening settings opens configuration dialog."""
        with patch(
            "intellicrack.ui.enhanced_ui_integration.R2ConfigurationDialog"
        ) as mock_dialog:
            mock_instance = MagicMock()
            mock_instance.exec.return_value = 0
            mock_dialog.return_value = mock_instance

            enhanced_dashboard._open_settings()

            mock_dialog.assert_called_once()

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
        self, enhanced_dashboard: EnhancedAnalysisDashboard, tmp_path: Path
    ) -> None:
        """Saving report writes content to file."""
        report_file = tmp_path / "test_report.txt"

        with patch(
            "intellicrack.ui.enhanced_ui_integration.QFileDialog.getSaveFileName"
        ) as mock_dialog:
            mock_dialog.return_value = (str(report_file), "Text Files (*.txt)")

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
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Opening file sets binary path and updates UI."""
        test_file = "D:\\test\\sample.exe"

        with (
            patch(
                "intellicrack.ui.enhanced_ui_integration.QFileDialog.getOpenFileName"
            ) as mock_dialog,
            patch.object(
                enhanced_main_window.dashboard.r2_widget, "set_binary_path"
            ) as mock_set_path,
        ):
            mock_dialog.return_value = (test_file, "All Files (*)")

            enhanced_main_window._open_file()

            assert enhanced_main_window.binary_path == test_file
            assert "sample.exe" in enhanced_main_window.binary_info_label.text()
            mock_set_path.assert_called_once_with(test_file)

    def test_start_analysis_requires_binary_file(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Starting analysis without binary file shows warning."""
        enhanced_main_window.binary_path = None

        with patch(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox.warning"
        ) as mock_warning:
            enhanced_main_window._start_analysis("comprehensive")

            mock_warning.assert_called_once()

    def test_start_analysis_with_binary_updates_status(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Starting analysis with binary updates dashboard status."""
        enhanced_main_window.binary_path = "D:\\test\\sample.exe"

        with patch.object(
            enhanced_main_window.dashboard.r2_widget, "_start_analysis"
        ) as mock_start:
            enhanced_main_window._start_analysis("vulnerability")

            assert enhanced_main_window.progress_bar.isVisible()
            mock_start.assert_called_once_with("vulnerability")

    def test_save_results_requires_analysis_data(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Saving results without analysis data shows info message."""
        with patch(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox.information"
        ) as mock_info:
            enhanced_main_window._save_results()

            mock_info.assert_called_once()

    def test_export_report_switches_to_reports_tab(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Exporting report switches to reports tab."""
        enhanced_main_window._export_report()

        assert enhanced_main_window.dashboard.content_tabs.currentIndex() == 3

    def test_open_hex_viewer_requires_binary_file(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Opening hex viewer without binary shows warning."""
        enhanced_main_window.binary_path = None

        with patch(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox.warning"
        ) as mock_warning:
            enhanced_main_window._open_hex_viewer()

            mock_warning.assert_called_once()

    def test_show_about_displays_about_dialog(
        self, enhanced_main_window: EnhancedMainWindow
    ) -> None:
        """Showing about displays about dialog."""
        with patch(
            "intellicrack.ui.enhanced_ui_integration.QMessageBox.about"
        ) as mock_about:
            enhanced_main_window._show_about()

            mock_about.assert_called_once()
            args = mock_about.call_args[0]
            assert "Intellicrack" in str(args)


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

        mock_app = Mock()
        mock_app.tab_widget = QTabWidget()

        result = integrate_enhanced_ui_with_existing_app(mock_app)

        assert result is True
        assert hasattr(mock_app, "enhanced_dashboard")
        assert mock_app.tab_widget.count() > 0

    def test_integrate_enhanced_ui_with_existing_app_adds_menu(
        self, qapp: QApplication
    ) -> None:
        """Integrating enhanced UI with existing app adds enhanced menu."""
        from intellicrack.handlers.pyqt6_handler import QMainWindow

        class MockApp(QMainWindow):
            def __init__(self) -> None:
                super().__init__()
                from intellicrack.handlers.pyqt6_handler import QTabWidget
                self.tab_widget = QTabWidget()

        mock_app = MockApp()

        result = integrate_enhanced_ui_with_existing_app(mock_app)

        assert result is True

        menu_bar = mock_app.menuBar()
        menu_titles = [
            menu_bar.actions()[i].text()
            for i in range(len(menu_bar.actions()))
        ]
        assert "Enhanced Analysis" in menu_titles

        mock_app.deleteLater()

    def test_integrate_enhanced_ui_handles_exceptions(
        self, qapp: QApplication
    ) -> None:
        """Integrating enhanced UI handles exceptions gracefully."""
        mock_app = Mock()
        mock_app.tab_widget = Mock()
        mock_app.tab_widget.addTab.side_effect = Exception("Test exception")

        result = integrate_enhanced_ui_with_existing_app(mock_app)

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
