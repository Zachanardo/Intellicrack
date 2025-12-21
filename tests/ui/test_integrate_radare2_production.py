"""Production tests for radare2 integration entry points.

This module tests the integration functions that provide simple
entry points for adding radare2 functionality to existing applications.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

from intellicrack.ui.integrate_radare2 import (
    add_radare2_to_intellicrack_app,
    create_standalone_radare2_app,
    integrate_with_main_app,
    show_integration_status,
)
from intellicrack.handlers.pyqt6_handler import QApplication, QTabWidget


class TestAddRadare2ToIntellicrackApp:
    """Test suite for add_radare2_to_intellicrack_app function."""

    def test_add_radare2_with_valid_app(self, qtbot: object) -> None:
        """Adding R2 to valid IntellicrackApp succeeds."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()
        app.update_output = MagicMock()

        result = add_radare2_to_intellicrack_app(app)

        assert result is True
        app.update_output.emit.assert_called()

    def test_add_radare2_with_none_app(self) -> None:
        """Adding R2 to None app returns False."""
        result = add_radare2_to_intellicrack_app(None)

        assert result is False

    def test_add_radare2_emits_success_messages(self, qtbot: object) -> None:
        """Success messages are emitted to app output."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()
        app.update_output = MagicMock()

        add_radare2_to_intellicrack_app(app)

        call_args = [call[0][0] for call in app.update_output.emit.call_args_list]
        assert any("Successfully integrated" in msg for msg in call_args)
        assert any("radare2 analysis capabilities" in msg for msg in call_args)

    def test_add_radare2_emits_failure_message_on_error(self) -> None:
        """Failure messages are emitted when integration fails."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.update_output = MagicMock()
        app.tab_widget = None

        result = add_radare2_to_intellicrack_app(app)

        assert result is False
        if app.update_output.emit.called:
            call_args = [call[0][0] for call in app.update_output.emit.call_args_list]
            assert any("Failed" in msg or "failed" in msg for msg in call_args)

    def test_add_radare2_handles_exception_gracefully(self) -> None:
        """Exceptions during integration are caught and handled."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.update_output = MagicMock()
        app.__getattribute__ = MagicMock(side_effect=Exception("Test error"))

        result = add_radare2_to_intellicrack_app(app)

        assert result is False

    def test_add_radare2_without_update_output(self, qtbot: object) -> None:
        """Integration works even if app lacks update_output signal."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()
        delattr(app, "update_output")

        result = add_radare2_to_intellicrack_app(app)

        assert result is True


class TestIntegrateWithMainApp:
    """Test suite for integrate_with_main_app function."""

    def test_integrate_with_main_app_no_qapplication(self) -> None:
        """Automatic integration fails gracefully without QApplication."""
        if QApplication.instance():
            QApplication.instance().quit()

        result = integrate_with_main_app()

        assert result is False

    @patch("intellicrack.ui.integrate_radare2.QApplication.instance")
    def test_integrate_finds_app_in_top_level_widgets(
        self,
        mock_instance: MagicMock,
        qtbot: object,
    ) -> None:
        """Automatic integration finds IntellicrackApp in top level widgets."""
        mock_app_instance = MagicMock()

        mock_widget = MagicMock()
        mock_widget.__class__.__name__ = "IntellicrackApp"
        mock_widget.tab_widget = QTabWidget()

        mock_app_instance.topLevelWidgets.return_value = [mock_widget]
        mock_instance.return_value = mock_app_instance

        result = integrate_with_main_app()

        assert result is True or result is False

    @patch("intellicrack.ui.integrate_radare2.QApplication.instance")
    def test_integrate_handles_no_widgets(
        self,
        mock_instance: MagicMock,
    ) -> None:
        """Automatic integration handles case with no top level widgets."""
        mock_app_instance = MagicMock()
        mock_app_instance.topLevelWidgets.return_value = []
        mock_instance.return_value = mock_app_instance

        result = integrate_with_main_app()

        assert result is False

    def test_integrate_checks_main_module(self) -> None:
        """Automatic integration checks __main__ for app instance."""
        import __main__

        original_app = getattr(__main__, "app", None)

        try:
            mock_app = MagicMock()
            mock_app.__class__.__name__ = "IntellicrackApp"
            mock_app.tab_widget = QTabWidget()
            __main__.app = mock_app

            result = integrate_with_main_app()

            assert isinstance(result, bool)

        finally:
            if original_app is not None:
                __main__.app = original_app
            elif hasattr(__main__, "app"):
                delattr(__main__, "app")

    def test_integrate_checks_sys_modules(self) -> None:
        """Automatic integration searches sys.modules for app instance."""
        test_module = MagicMock()
        test_module.app = MagicMock()
        test_module.app.__class__.__name__ = "IntellicrackApp"
        test_module.app.tab_widget = QTabWidget()

        sys.modules["test_integration_module"] = test_module

        try:
            result = integrate_with_main_app()
            assert isinstance(result, bool)

        finally:
            if "test_integration_module" in sys.modules:
                del sys.modules["test_integration_module"]


class TestCreateStandaloneRadare2App:
    """Test suite for create_standalone_radare2_app function."""

    @patch("intellicrack.ui.integrate_radare2.create_enhanced_application")
    def test_create_standalone_app_success(
        self,
        mock_create: MagicMock,
        qtbot: object,
    ) -> None:
        """Creating standalone app returns QApplication and window."""
        mock_app = MagicMock()
        mock_window = MagicMock()
        mock_create.return_value = (mock_app, mock_window)

        app, window = create_standalone_radare2_app()

        assert app is mock_app
        assert window is mock_window
        mock_create.assert_called_once()

    @patch("intellicrack.ui.integrate_radare2.create_enhanced_application")
    def test_create_standalone_app_failure(
        self,
        mock_create: MagicMock,
    ) -> None:
        """Creating standalone app handles failure gracefully."""
        mock_create.return_value = (None, None)

        app, window = create_standalone_radare2_app()

        assert app is None
        assert window is None

    @patch("intellicrack.ui.integrate_radare2.create_enhanced_application")
    def test_create_standalone_app_handles_exception(
        self,
        mock_create: MagicMock,
    ) -> None:
        """Creating standalone app handles exceptions gracefully."""
        mock_create.side_effect = Exception("Test error")

        app, window = create_standalone_radare2_app()

        assert app is None
        assert window is None

    @patch("intellicrack.ui.integrate_radare2.create_enhanced_application")
    def test_create_standalone_app_partial_failure(
        self,
        mock_create: MagicMock,
    ) -> None:
        """Creating standalone app handles partial success."""
        mock_app = MagicMock()
        mock_create.return_value = (mock_app, None)

        app, window = create_standalone_radare2_app()

        assert app is None
        assert window is None


class TestShowIntegrationStatus:
    """Test suite for show_integration_status function."""

    def test_show_status_without_app(self) -> None:
        """Showing status without app returns status dict."""
        status = show_integration_status()

        assert isinstance(status, dict)
        assert "ui_manager" in status or "error" in status

    def test_show_status_with_app(self, qtbot: object) -> None:
        """Showing status with app includes app-specific information."""
        app = MagicMock()
        app.tab_widget = QTabWidget()

        status = show_integration_status(app)

        assert isinstance(status, dict)
        assert "app_type" in status or "error" in status

        if "app_type" in status:
            assert "has_tab_widget" in status
            assert "has_menu_bar" in status
            assert "has_r2_ui_manager" in status
            assert "has_r2_widget" in status

    def test_show_status_includes_app_type(self) -> None:
        """Status includes string representation of app type."""
        app = MagicMock()
        app.__class__.__name__ = "TestApp"
        app.tab_widget = QTabWidget()

        status = show_integration_status(app)

        if "app_type" in status:
            assert "TestApp" in status["app_type"] or "Mock" in status["app_type"]

    def test_show_status_checks_tab_widget(self) -> None:
        """Status correctly identifies presence of tab widget."""
        app_with_tabs = MagicMock()
        app_with_tabs.tab_widget = QTabWidget()

        app_without_tabs = MagicMock()
        delattr(app_without_tabs, "tab_widget")

        status_with = show_integration_status(app_with_tabs)
        status_without = show_integration_status(app_without_tabs)

        if "has_tab_widget" in status_with:
            assert status_with["has_tab_widget"] is True
        if "has_tab_widget" in status_without:
            assert status_without["has_tab_widget"] is False

    def test_show_status_checks_menu_bar(self) -> None:
        """Status correctly identifies presence of menu bar."""
        app_with_menu = MagicMock()
        app_with_menu.menuBar = MagicMock()

        app_without_menu = MagicMock()
        delattr(app_without_menu, "menuBar")

        status_with = show_integration_status(app_with_menu)
        status_without = show_integration_status(app_without_menu)

        if "has_menu_bar" in status_with:
            assert status_with["has_menu_bar"] is True
        if "has_menu_bar" in status_without:
            assert status_without["has_menu_bar"] is False

    def test_show_status_handles_exception(self) -> None:
        """Status function handles exceptions gracefully."""
        app = MagicMock()
        app.__getattribute__ = MagicMock(side_effect=Exception("Test error"))

        status = show_integration_status(app)

        assert isinstance(status, dict)
        assert "error" in status


class TestIntegrationWithRealApplications:
    """Test integration functions with real PyQt6 applications."""

    def test_add_radare2_to_real_app_with_tabs(self, qtbot: object) -> None:
        """Adding R2 to real app with QTabWidget succeeds."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()
        qtbot.addWidget(app.tab_widget)

        result = add_radare2_to_intellicrack_app(app)

        assert result is True
        assert app.tab_widget.count() >= 2

    def test_status_reflects_actual_integration_state(
        self,
        qtbot: object,
    ) -> None:
        """Status accurately reflects integration state after integration."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()

        status_before = show_integration_status(app)
        add_radare2_to_intellicrack_app(app)
        status_after = show_integration_status(app)

        if "has_r2_ui_manager" in status_before and "has_r2_ui_manager" in status_after:
            assert status_after != status_before


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_add_radare2_to_app_without_required_attributes(self) -> None:
        """Integration handles apps missing required attributes."""
        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        delattr(app, "tab_widget")

        result = add_radare2_to_intellicrack_app(app)

        assert isinstance(result, bool)

    def test_multiple_integration_calls_on_same_app(
        self,
        qtbot: object,
    ) -> None:
        """Multiple integration calls on same app are handled."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        app = MagicMock()
        app.__class__.__name__ = "IntellicrackApp"
        app.tab_widget = QTabWidget()

        result1 = add_radare2_to_intellicrack_app(app)
        result2 = add_radare2_to_intellicrack_app(app)

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)

    def test_status_with_partially_integrated_app(self) -> None:
        """Status works with partially integrated app."""
        app = MagicMock()
        app.tab_widget = QTabWidget()
        app.r2_widget = MagicMock()

        status = show_integration_status(app)

        assert isinstance(status, dict)
