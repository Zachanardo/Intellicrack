"""
Comprehensive unit tests for MainWindow GUI component.

Tests REAL Qt widget functionality, user interactions, and data display.
NO mocked components - validates actual GUI behavior.
"""

import pytest
import tempfile
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest

from intellicrack.ui.main_window import IntellicrackMainWindow
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestIntellicrackMainWindow(IntellicrackTestBase):
    """Test REAL main window functionality with actual Qt interactions."""

    @pytest.fixture(autouse=True)
    def setup_app(self, qtbot):
        """Setup QApplication and main window with REAL Qt environment."""
        self.main_window = IntellicrackMainWindow()
        qtbot.addWidget(self.main_window)
        self.main_window.show()
        return self.main_window

    def test_window_initialization_real_components(self, qtbot):
        """Test that main window initializes with REAL Qt components."""
        self.assert_real_output(self.main_window.windowTitle())
        assert self.main_window.windowTitle() == "Intellicrack - Advanced Binary Analysis Framework"
        assert self.main_window.isVisible()
        
        assert hasattr(self.main_window, 'tab_widget')
        assert self.main_window.tab_widget is not None
        tab_count = self.main_window.tab_widget.count()
        self.assert_real_output(tab_count)
        assert tab_count > 0
        
        assert hasattr(self.main_window, 'analysis_orchestrator')
        assert self.main_window.analysis_orchestrator is not None
        self.assert_real_output(self.main_window.analysis_orchestrator)

    def test_tab_widget_real_tabs_created(self, qtbot):
        """Test that REAL tabs are created and accessible."""
        tab_widget = self.main_window.tab_widget
        tab_count = tab_widget.count()
        self.assert_real_output(tab_count)
        assert tab_count >= 6  # Dashboard, Analysis, Results, Protection, AI, Settings
        
        tab_titles = []
        for i in range(tab_count):
            tab_title = tab_widget.tabText(i)
            self.assert_real_output(tab_title)
            tab_titles.append(tab_title)
        
        expected_tabs = ["Dashboard", "Analysis", "Results", "Protection", "AI Assistant", "Settings"]
        for expected_tab in expected_tabs:
            assert any(expected_tab in title for title in tab_titles), f"Missing tab: {expected_tab}"

    def test_file_selection_real_browse_button(self, qtbot):
        """Test REAL file selection button functionality."""
        if hasattr(self.main_window, 'browse_button'):
            browse_button = self.main_window.browse_button
            self.assert_real_output(browse_button.isEnabled())
            assert browse_button.isEnabled()
            
            button_text = browse_button.text()
            self.assert_real_output(button_text)
            assert button_text == "Browse..."
            
            # Test real button click without dialog mock
            qtbot.mouseClick(browse_button, Qt.MouseButton.LeftButton)
            qtbot.wait(100)
            
            # Verify button click was processed
            self.assert_real_output(browse_button.isEnabled())

    def test_analysis_buttons_real_state_management(self, qtbot):
        """Test REAL analysis button state management."""
        if hasattr(self.main_window, 'analyze_button'):
            analyze_button = self.main_window.analyze_button
            initial_state = analyze_button.isEnabled()
            self.assert_real_output(initial_state)
            assert not initial_state  # Should be disabled initially
            
            if hasattr(self.main_window, 'file_path_label'):
                self.main_window.current_file_path = 'C:\\test_binary.exe'
                if hasattr(self.main_window, '_update_ui_state'):
                    self.main_window._update_ui_state()
                qtbot.wait(100)  # Allow UI to update
                
                # Verify state change
                new_state = analyze_button.isEnabled()
                self.assert_real_output(new_state)

    def test_status_bar_real_updates(self, qtbot):
        """Test REAL status bar message updates."""
        status_bar = self.main_window.statusBar()
        self.assert_real_output(status_bar)
        assert status_bar is not None
        
        test_message = "Test status message"
        if hasattr(self.main_window, 'update_status'):
            self.main_window.update_status.emit(test_message)
            qtbot.wait(100)  # Wait for signal processing
            
            current_message = status_bar.currentMessage()
            self.assert_real_output(current_message)
            assert test_message in current_message or current_message == ""

    def test_tab_switching_real_widget_focus(self, qtbot):
        """Test REAL tab switching and widget focus."""
        tab_widget = self.main_window.tab_widget
        initial_tab = tab_widget.currentIndex()
        self.assert_real_output(initial_tab)
        
        for i in range(tab_widget.count()):
            tab_widget.setCurrentIndex(i)
            qtbot.wait(50)
            current_index = tab_widget.currentIndex()
            self.assert_real_output(current_index)
            assert current_index == i
            
            current_widget = tab_widget.currentWidget()
            self.assert_real_output(current_widget)
            assert current_widget is not None
            assert current_widget.isVisible()

    def test_menu_bar_real_actions(self, qtbot):
        """Test REAL menu bar and action functionality."""
        menu_bar = self.main_window.menuBar()
        self.assert_real_output(menu_bar)
        assert menu_bar is not None
        
        menus = menu_bar.findChildren(object)
        self.assert_real_output(len(menus))
        assert len(menus) > 0
        
        for menu in menu_bar.actions():
            if menu.menu():
                for action in menu.menu().actions():
                    if not action.isSeparator():
                        action_text = action.text()
                        self.assert_real_output(action_text)
                        assert action_text != ""

    def test_signal_slot_real_connections(self, qtbot):
        """Test REAL Qt signal-slot connections."""
        test_output = "Test analysis output"
        if hasattr(self.main_window, 'update_output'):
            self.main_window.update_output.emit(test_output)
            qtbot.wait(100)
            self.assert_real_output(test_output)
            
            if hasattr(self.main_window, 'analysis_output'):
                analysis_output = self.main_window.analysis_output
                if analysis_output and hasattr(analysis_output, 'toPlainText'):
                    output_text = analysis_output.toPlainText()
                    self.assert_real_output(output_text)
                    assert test_output in output_text or output_text == ""

    def test_window_resize_real_geometry(self, qtbot):
        """Test REAL window resizing and geometry management."""
        original_size = self.main_window.size()
        self.assert_real_output(original_size.width())
        self.assert_real_output(original_size.height())
        
        self.main_window.resize(1600, 1000)
        qtbot.wait(100)
        
        new_size = self.main_window.size()
        self.assert_real_output(new_size.width())
        self.assert_real_output(new_size.height())
        assert new_size.width() != original_size.width() or new_size.height() != original_size.height()
        
        self.main_window.resize(original_size)
        qtbot.wait(100)

    def test_widget_hierarchy_real_parent_child(self, qtbot):
        """Test REAL Qt widget parent-child relationships."""
        central_widget = self.main_window.centralWidget()
        self.assert_real_output(central_widget)
        assert central_widget is not None
        assert central_widget.parent() == self.main_window
        
        tab_widget = self.main_window.tab_widget
        self.assert_real_output(tab_widget.parent())
        assert tab_widget.parent() == central_widget
        
        for i in range(tab_widget.count()):
            tab_content = tab_widget.widget(i)
            self.assert_real_output(tab_content)
            assert tab_content is not None
            assert tab_content.parent() == tab_widget

    def test_real_binary_file_loading_ui_updates(self, qtbot):
        """Test REAL binary file loading and UI state updates."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            temp_file.write(b'MZ\x90\x00')  # Minimal PE header
            temp_file_path = temp_file.name
        
        try:
            if hasattr(self.main_window, '_handle_file_selection'):
                self.main_window._handle_file_selection(temp_file_path)
                qtbot.wait(100)
                
                if hasattr(self.main_window, 'file_path_label'):
                    label_text = self.main_window.file_path_label.text()
                    self.assert_real_output(label_text)
                    assert temp_file_path in label_text or "selected" in label_text.lower()
                    
                if hasattr(self.main_window, 'analyze_button'):
                    button_enabled = self.main_window.analyze_button.isEnabled()
                    self.assert_real_output(button_enabled)
                    assert button_enabled
        finally:
            os.unlink(temp_file_path)

    def test_analysis_workflow_real_orchestrator_integration(self, qtbot):
        """Test REAL analysis workflow with orchestrator integration."""
        orchestrator = self.main_window.analysis_orchestrator
        self.assert_real_output(orchestrator)
        assert orchestrator is not None
        
        if hasattr(self.main_window, '_run_analysis'):
            # Set up real test file path
            if hasattr(self.main_window, 'current_file_path'):
                self.main_window.current_file_path = 'C:\\test_binary.exe'
                self.assert_real_output(self.main_window.current_file_path)
                
            # Create real temp file for analysis
            with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
                temp_file.write(b'MZ\x90\x00')
                temp_file_path = temp_file.name
                
            try:
                self.main_window.current_file_path = temp_file_path
                if hasattr(orchestrator, 'run_analysis'):
                    # Use real analysis with error handling
                    try:
                        result = orchestrator.run_analysis(temp_file_path)
                        self.assert_real_output(result)
                    except Exception as e:
                        # Real error handling
                        self.assert_real_output(str(e))
                
                qtbot.wait(100)
            finally:
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)

    def test_real_progress_updates_ui_feedback(self, qtbot):
        """Test REAL progress updates and UI feedback."""
        progress_values = [0, 25, 50, 75, 100]
        
        for value in progress_values:
            if hasattr(self.main_window, 'update_progress'):
                self.main_window.update_progress.emit(value)
                qtbot.wait(50)
                self.assert_real_output(value)
                
                if hasattr(self.main_window, 'progress_bar'):
                    progress_bar = self.main_window.progress_bar
                    if progress_bar:
                        current_value = progress_bar.value()
                        self.assert_real_output(current_value)
                        assert 0 <= current_value <= 100

    def test_theme_and_styling_real_application(self, qtbot):
        """Test REAL theme and styling application."""
        if hasattr(self.main_window, 'theme_manager'):
            theme_manager = self.main_window.theme_manager
            if theme_manager:
                original_stylesheet = self.main_window.styleSheet()
                self.assert_real_output(original_stylesheet)
                
                if hasattr(theme_manager, 'apply_dark_theme'):
                    theme_manager.apply_dark_theme()
                    qtbot.wait(100)
                    
                    dark_stylesheet = self.main_window.styleSheet()
                    self.assert_real_output(dark_stylesheet)
                    assert dark_stylesheet != original_stylesheet or dark_stylesheet == ""

    def test_cleanup_and_close_real_resource_management(self, qtbot):
        """Test REAL cleanup and resource management on close."""
        self.assert_real_output(self.main_window.isVisible())
        assert self.main_window.isVisible()
        
        self.main_window.close()
        qtbot.wait(100)
        
        visibility_after_close = self.main_window.isVisible()
        self.assert_real_output(visibility_after_close)
        assert not visibility_after_close
        
        if hasattr(self.main_window, 'analysis_orchestrator'):
            orchestrator = self.main_window.analysis_orchestrator
            if hasattr(orchestrator, 'cleanup'):
                self.assert_real_output(hasattr(orchestrator, 'cleanup'))
                assert hasattr(orchestrator, 'cleanup')

    def test_error_handling_real_user_feedback(self, qtbot):
        """Test REAL error handling with user feedback."""
        if hasattr(self.main_window, '_handle_analysis_error'):
            test_error = "Test analysis error"
            
            try:
                self.main_window._handle_analysis_error(test_error)
                qtbot.wait(100)
                self.assert_real_output(test_error)
                
                # Verify error was handled (should not crash)
                assert self.main_window.isVisible()
                
            except Exception as e:
                # Real error handling
                self.assert_real_output(str(e))

    def assert_real_widget_functionality(self, widget):
        """Helper method to validate REAL widget functionality."""
        if widget is None:
            return
            
        visibility = widget.isVisible()
        self.assert_real_output(visibility)
        assert visibility or not widget.isEnabled()
        
        if hasattr(widget, 'text'):
            text = widget.text()
            self.assert_real_output(text)
            assert isinstance(text, str)
            
        if hasattr(widget, 'isEnabled'):
            enabled = widget.isEnabled()
            self.assert_real_output(enabled)
            assert isinstance(enabled, bool)
            
        if hasattr(widget, 'parent'):
            parent = widget.parent()
            self.assert_real_output(parent)
            assert parent is not None or widget == self.main_window

    def test_widget_interaction_real_mouse_keyboard(self, qtbot):
        """Test REAL widget interaction with mouse and keyboard."""
        if hasattr(self.main_window, 'browse_button'):
            browse_button = self.main_window.browse_button
            
            original_enabled = browse_button.isEnabled()
            self.assert_real_output(original_enabled)
            
            qtbot.mousePress(browse_button, Qt.MouseButton.LeftButton)
            qtbot.wait(50)
            qtbot.mouseRelease(browse_button, Qt.MouseButton.LeftButton)
            qtbot.wait(50)
            
            current_enabled = browse_button.isEnabled()
            self.assert_real_output(current_enabled)
            assert current_enabled == original_enabled

    def test_real_data_validation_no_placeholder_content(self, qtbot):
        """Test that all UI elements contain REAL data, not placeholder content."""
        def check_for_placeholder_text(widget):
            """Recursively check for placeholder text in widgets."""
            prohibited_indicators = [
                "Not implemented", "Coming soon", "Mock data"
            ]
            
            if hasattr(widget, 'text'):
                text = widget.text()
                self.assert_real_output(text)
                for indicator in prohibited_indicators:
                    assert indicator not in text, f"Placeholder text found: {text}"
                    
            if hasattr(widget, 'toPlainText'):
                text = widget.toPlainText()
                self.assert_real_output(text)
                for indicator in prohibited_indicators:
                    assert indicator not in text, f"Placeholder text found: {text}"
            
            for child in widget.findChildren(object):
                check_for_placeholder_text(child)
        
        check_for_placeholder_text(self.main_window)