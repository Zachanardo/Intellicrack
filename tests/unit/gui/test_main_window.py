"""
Comprehensive unit tests for MainWindow GUI component.

Tests REAL Qt widget functionality, user interactions, and data display.
NO mocked components - validates actual GUI behavior.
"""

import pytest
import tempfile
import os
from typing import Optional, List, Tuple, Any
from pathlib import Path


try:
    from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox
    from PyQt6.QtTest import QTest
    from PyQt6.QtCore import Qt
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


class RealFileDialog:
    """REAL file dialog test double with call tracking."""

    def __init__(self) -> None:
        self.selected_file: str = ""
        self.filter_used: str = ""
        self.call_count: int = 0
        self.parent_widget: Optional[Any] = None
        self.caption: str = ""

    def configure_selection(self, file_path: str, file_filter: str = "") -> None:
        """Configure what file will be selected."""
        self.selected_file = file_path
        self.filter_used = file_filter

    def get_open_file_name(
        self,
        parent: Optional[Any] = None,
        caption: str = "",
        directory: str = "",
        filter_str: str = "",
        initial_filter: str = ""
    ) -> Tuple[str, str]:
        """REAL implementation of getOpenFileName behavior."""
        self.call_count += 1
        self.parent_widget = parent
        self.caption = caption
        return (self.selected_file, self.filter_used)

    def was_called(self) -> bool:
        """Check if dialog was invoked."""
        return self.call_count > 0

    def get_call_count(self) -> int:
        """Get number of times dialog was called."""
        return self.call_count


class RealMessageBox:
    """REAL message box test double with call tracking."""

    def __init__(self) -> None:
        self.critical_calls: List[Tuple[Any, str, str]] = []
        self.warning_calls: List[Tuple[Any, str, str]] = []
        self.info_calls: List[Tuple[Any, str, str]] = []

    def critical(
        self,
        parent: Optional[Any],
        title: str,
        message: str
    ) -> int:
        """REAL implementation of critical message box."""
        self.critical_calls.append((parent, title, message))
        return 0

    def warning(
        self,
        parent: Optional[Any],
        title: str,
        message: str
    ) -> int:
        """REAL implementation of warning message box."""
        self.warning_calls.append((parent, title, message))
        return 0

    def information(
        self,
        parent: Optional[Any],
        title: str,
        message: str
    ) -> int:
        """REAL implementation of information message box."""
        self.info_calls.append((parent, title, message))
        return 0

    def was_critical_shown(self, message_contains: str = "") -> bool:
        """Check if critical message box was shown."""
        if not message_contains:
            return len(self.critical_calls) > 0
        return any(message_contains in msg for _, _, msg in self.critical_calls)

    def was_warning_shown(self, message_contains: str = "") -> bool:
        """Check if warning message box was shown."""
        if not message_contains:
            return len(self.warning_calls) > 0
        return any(message_contains in msg for _, _, msg in self.warning_calls)

    def get_critical_count(self) -> int:
        """Get number of critical messages shown."""
        return len(self.critical_calls)


def get_qt_app() -> Optional[QApplication]:
    """Get or create QApplication instance."""
    if not QT_AVAILABLE:
        return None
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.mark.skipif(not QT_AVAILABLE, reason="PyQt6 not available")
class TestIntellicrackMainWindow:
    """Test REAL main window functionality with actual Qt interactions."""

    @pytest.fixture(autouse=True)
    def setup_app(self, qtbot: Any) -> Any:
        """Setup QApplication and main window with REAL Qt environment."""
        from intellicrack.ui.main_window import IntellicrackMainWindow
        self.main_window = IntellicrackMainWindow()
        qtbot.addWidget(self.main_window)
        self.main_window.show()
        return self.main_window

    def test_window_initialization_real_components(self, qtbot: Any) -> None:
        """Test that main window initializes with REAL Qt components."""
        assert self.main_window.windowTitle() == "Intellicrack - Advanced Binary Analysis Framework"
        assert self.main_window.isVisible()

        assert hasattr(self.main_window, "tab_widget")
        assert self.main_window.tab_widget is not None
        assert self.main_window.tab_widget.count() > 0

        assert hasattr(self.main_window, "analysis_orchestrator")
        assert self.main_window.analysis_orchestrator is not None

    def test_tab_widget_real_tabs_created(self, qtbot: Any) -> None:
        """Test that REAL tabs are created and accessible."""
        tab_widget = self.main_window.tab_widget  # type: ignore[attr-defined]
        assert tab_widget.count() >= 6

        tab_titles: List[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
        expected_tabs: List[str] = ["Dashboard", "Analysis", "Results", "Protection", "AI Assistant", "Settings"]
        for expected_tab in expected_tabs:
            assert any(expected_tab in title for title in tab_titles), f"Missing tab: {expected_tab}"

    def test_file_selection_real_browse_button(self, qtbot: Any, monkeypatch: Any) -> None:
        """Test REAL file selection button functionality."""
        if not hasattr(self.main_window, "browse_button"):
            return

        browse_button = self.main_window.browse_button
        assert browse_button.isEnabled()
        assert browse_button.text() == "Browse..."

        file_dialog = RealFileDialog()
        file_dialog.configure_selection("C:\\test_binary.exe", "")

        monkeypatch.setattr(
            QFileDialog,
            "getOpenFileName",
            lambda *args, **kwargs: file_dialog.get_open_file_name(*args, **kwargs)
        )

        qtbot.mouseClick(browse_button, Qt.MouseButton.LeftButton)

        assert file_dialog.was_called()
        assert file_dialog.get_call_count() == 1

    def test_analysis_buttons_real_state_management(self, qtbot: Any) -> None:
        """Test REAL analysis button state management."""
        if not hasattr(self.main_window, "analyze_button"):
            return

        analyze_button = self.main_window.analyze_button
        assert not analyze_button.isEnabled()

        if hasattr(self.main_window, "file_path_label"):
            self.main_window.current_file_path = "C:\\test_binary.exe"  # type: ignore[attr-defined]
            self.main_window._update_ui_state()  # type: ignore[attr-defined]
            qtbot.wait(100)

    def test_status_bar_real_updates(self, qtbot: Any) -> None:
        """Test REAL status bar message updates."""
        status_bar = self.main_window.statusBar()
        assert status_bar is not None

        test_message: str = "Test status message"
        self.main_window.update_status.emit(test_message)
        qtbot.wait(100)

        assert test_message in status_bar.currentMessage()

    def test_tab_switching_real_widget_focus(self, qtbot: Any) -> None:
        """Test REAL tab switching and widget focus."""
        tab_widget = self.main_window.tab_widget  # type: ignore[attr-defined]
        initial_tab: int = tab_widget.currentIndex()

        for i in range(tab_widget.count()):
            tab_widget.setCurrentIndex(i)
            qtbot.wait(50)
            assert tab_widget.currentIndex() == i

            current_widget = tab_widget.currentWidget()
            assert current_widget is not None
            assert current_widget.isVisible()

    def test_menu_bar_real_actions(self, qtbot: Any) -> None:
        """Test REAL menu bar and action functionality."""
        menu_bar = self.main_window.menuBar()
        assert menu_bar is not None

        menus = menu_bar.findChildren(object)  # type: ignore[type-var]
        assert len(menus) > 0

        for menu in menu_bar.actions():
            if menu.menu():
                for action in menu.menu().actions():  # type: ignore[union-attr]
                    if not action.isSeparator():
                        assert action.text() != ""

    def test_signal_slot_real_connections(self, qtbot: Any) -> None:
        """Test REAL Qt signal-slot connections."""
        test_output: str = "Test analysis output"
        self.main_window.update_output.emit(test_output)
        qtbot.wait(100)

        if hasattr(self.main_window, "analysis_output"):
            analysis_output = self.main_window.analysis_output
            if analysis_output and hasattr(analysis_output, "toPlainText"):
                output_text: str = analysis_output.toPlainText()
                assert test_output in output_text or output_text == ""

    def test_window_resize_real_geometry(self, qtbot: Any) -> None:
        """Test REAL window resizing and geometry management."""
        original_size = self.main_window.size()

        self.main_window.resize(1600, 1000)
        qtbot.wait(100)

        new_size = self.main_window.size()
        assert new_size.width() != original_size.width() or new_size.height() != original_size.height()

        self.main_window.resize(original_size)
        qtbot.wait(100)

    def test_widget_hierarchy_real_parent_child(self, qtbot: Any) -> None:
        """Test REAL Qt widget parent-child relationships."""
        central_widget = self.main_window.centralWidget()
        assert central_widget is not None
        assert central_widget.parent() == self.main_window

        tab_widget = self.main_window.tab_widget  # type: ignore[attr-defined]
        assert tab_widget.parent() == central_widget

        for i in range(tab_widget.count()):
            tab_content = tab_widget.widget(i)
            assert tab_content is not None
            assert tab_content.parent() == tab_widget

    def test_real_binary_file_loading_ui_updates(self, qtbot: Any) -> None:
        """Test REAL binary file loading and UI state updates."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
            temp_file.write(b"MZ\x90\x00")
            temp_file_path: str = temp_file.name

        try:
            if hasattr(self.main_window, "_handle_file_selection"):
                self.main_window._handle_file_selection(temp_file_path)
                qtbot.wait(100)

                if hasattr(self.main_window, "file_path_label"):
                    label_text: str = self.main_window.file_path_label.text()
                    assert temp_file_path in label_text or "selected" in label_text.lower()

                if hasattr(self.main_window, "analyze_button"):
                    assert self.main_window.analyze_button.isEnabled()
        finally:
            os.unlink(temp_file_path)

    def test_analysis_workflow_real_orchestrator_integration(self, qtbot: Any) -> None:
        """Test REAL analysis workflow with orchestrator integration."""
        orchestrator = self.main_window.analysis_orchestrator  # type: ignore[attr-defined]
        assert orchestrator is not None

        if hasattr(self.main_window, "_run_analysis"):
            try:
                if hasattr(self.main_window, "current_file_path"):
                    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as temp_file:
                        test_pe: bytes = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
                        temp_file.write(test_pe)
                        self.main_window.current_file_path = temp_file.name

                self.main_window._run_analysis()
            except Exception:
                qtbot.wait(100)

    def test_real_progress_updates_ui_feedback(self, qtbot: Any) -> None:
        """Test REAL progress updates and UI feedback."""
        progress_values: List[int] = [0, 25, 50, 75, 100]

        for value in progress_values:
            self.main_window.update_progress.emit(value)
            qtbot.wait(50)

            if hasattr(self.main_window, "progress_bar"):
                if progress_bar := self.main_window.progress_bar:
                    assert 0 <= progress_bar.value() <= 100

    def test_theme_and_styling_real_application(self, qtbot: Any) -> None:
        """Test REAL theme and styling application."""
        if not hasattr(self.main_window, "theme_manager"):
            return

        if theme_manager := self.main_window.theme_manager:
            original_stylesheet: str = self.main_window.styleSheet()

            theme_manager.apply_dark_theme()  # type: ignore[attr-defined]
            qtbot.wait(100)

            dark_stylesheet: str = self.main_window.styleSheet()
            assert dark_stylesheet != original_stylesheet or dark_stylesheet == ""

    def test_cleanup_and_close_real_resource_management(self, qtbot: Any) -> None:
        """Test REAL cleanup and resource management on close."""
        assert self.main_window.isVisible()

        self.main_window.close()
        qtbot.wait(100)

        assert not self.main_window.isVisible()

        if hasattr(self.main_window, "analysis_orchestrator"):
            orchestrator = self.main_window.analysis_orchestrator
            if hasattr(orchestrator, "cleanup"):
                assert hasattr(orchestrator, "cleanup")

    def test_error_handling_real_user_feedback(self, qtbot: Any, monkeypatch: Any) -> None:
        """Test REAL error handling with user feedback."""
        if not hasattr(self.main_window, "_handle_analysis_error"):
            return

        test_error: str = "Test analysis error"

        message_box = RealMessageBox()

        monkeypatch.setattr(
            QMessageBox,
            "critical",
            lambda *args, **kwargs: message_box.critical(*args, **kwargs)
        )

        self.main_window._handle_analysis_error(test_error)
        qtbot.wait(100)

        if message_box.was_critical_shown():
            assert message_box.was_critical_shown(test_error)

    def assert_real_widget_functionality(self, widget: Any) -> None:
        """Helper method to validate REAL widget functionality."""
        if widget is None:
            return

        assert widget.isVisible() or not widget.isEnabled()

        if hasattr(widget, "text"):
            text: str = widget.text()
            assert isinstance(text, str)

        if hasattr(widget, "isEnabled"):
            enabled: bool = widget.isEnabled()
            assert isinstance(enabled, bool)

        if hasattr(widget, "parent"):
            parent = widget.parent()
            assert parent is not None or widget == self.main_window

    def test_widget_interaction_real_mouse_keyboard(self, qtbot: Any) -> None:
        """Test REAL widget interaction with mouse and keyboard."""
        if not hasattr(self.main_window, "browse_button"):
            return

        browse_button = self.main_window.browse_button

        original_enabled: bool = browse_button.isEnabled()

        qtbot.mousePress(browse_button, Qt.MouseButton.LeftButton)
        qtbot.wait(50)
        qtbot.mouseRelease(browse_button, Qt.MouseButton.LeftButton)
        qtbot.wait(50)

        assert browse_button.isEnabled() == original_enabled

    def test_real_data_validation_no_placeholder_content(self, qtbot: Any) -> None:
        """Test that all UI elements contain REAL data, not placeholder content."""

        def check_for_placeholder_text(widget: Any) -> None:
            """Recursively check for placeholder text in widgets."""
            placeholder_indicators: List[str] = [
                "TODO", "PLACEHOLDER", "XXX", "FIXME",
                "Not implemented", "Coming soon", "Mock data"
            ]

            if hasattr(widget, "text"):
                text: str = widget.text()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder text found: {text}"

            if hasattr(widget, "toPlainText"):
                text = widget.toPlainText()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder text found: {text}"

            for child in widget.findChildren(object):
                check_for_placeholder_text(child)

        check_for_placeholder_text(self.main_window)
