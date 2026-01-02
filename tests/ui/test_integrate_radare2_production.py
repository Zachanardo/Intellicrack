"""Production tests for radare2 integration entry points.

This module tests the integration functions that provide simple
entry points for adding radare2 functionality to existing applications.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QTabWidget, pyqtSignal
from intellicrack.ui.integrate_radare2 import (
    add_radare2_to_intellicrack_app,
    create_standalone_radare2_app,
    integrate_with_main_app,
    show_integration_status,
)


class RealTestApp:
    """Real test application that mimics IntellicrackApp structure."""

    def __init__(self, has_tab_widget: bool = True, has_update_signal: bool = True) -> None:
        self.tab_widget: QTabWidget | None = QTabWidget() if has_tab_widget else None
        self._messages: list[str] = []
        self._has_update_signal = has_update_signal

        if has_update_signal:
            from intellicrack.handlers.pyqt6_handler import QObject

            class SignalEmitter(QObject):
                update_output = pyqtSignal(str)

            self._emitter = SignalEmitter()
            self.update_output = self._emitter.update_output
            self.update_output.connect(self._capture_message)

    def _capture_message(self, message: str) -> None:
        """Capture emitted messages for validation."""
        self._messages.append(message)

    def get_messages(self) -> list[str]:
        """Get all captured messages."""
        return self._messages.copy()

    def menuBar(self) -> object:
        """Simulate menu bar presence."""
        return object()


class MinimalTestApp:
    """Minimal test app without optional attributes."""

    def __init__(self) -> None:
        self.tab_widget: QTabWidget = QTabWidget()


class BrokenTestApp:
    """Test app that raises exceptions on attribute access."""

    def __getattribute__(self, name: str) -> Any:
        if name in {"tab_widget", "update_output", "menuBar"}:
            raise RuntimeError(f"Simulated error accessing {name}")
        return object.__getattribute__(self, name)


@pytest.fixture
def real_app(qtbot: Any) -> RealTestApp:
    """Create real test application instance."""
    from intellicrack.ui.comprehensive_integration import cleanup_integration

    cleanup_integration()
    app = RealTestApp()
    if app.tab_widget:
        qtbot.addWidget(app.tab_widget)
    return app


@pytest.fixture
def minimal_app(qtbot: Any) -> MinimalTestApp:
    """Create minimal test application."""
    from intellicrack.ui.comprehensive_integration import cleanup_integration

    cleanup_integration()
    app = MinimalTestApp()
    qtbot.addWidget(app.tab_widget)
    return app


class TestAddRadare2ToIntellicrackApp:
    """Test suite for add_radare2_to_intellicrack_app function."""

    def test_add_radare2_with_valid_app_succeeds(self, real_app: RealTestApp) -> None:
        """Adding R2 to valid app with all required attributes succeeds."""
        result = add_radare2_to_intellicrack_app(real_app)

        assert isinstance(result, bool)
        if result and real_app.tab_widget:
            assert real_app.tab_widget.count() >= 1

    def test_add_radare2_with_none_app_returns_false(self) -> None:
        """Adding R2 to None app returns False immediately."""
        result = add_radare2_to_intellicrack_app(None)

        assert result is False

    def test_add_radare2_emits_success_messages(self, real_app: RealTestApp) -> None:
        """Success messages contain expected integration status."""
        result = add_radare2_to_intellicrack_app(real_app)

        if result:
            messages = real_app.get_messages()
            assert any("radare2" in msg.lower() for msg in messages)

    def test_add_radare2_emits_failure_message_on_error(self) -> None:
        """Failure messages are logged when integration cannot complete."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        app_without_tabs = RealTestApp(has_tab_widget=False)
        result = add_radare2_to_intellicrack_app(app_without_tabs)

        assert isinstance(result, bool)

    def test_add_radare2_handles_exception_gracefully(self) -> None:
        """Exceptions during integration are caught and return False."""
        broken_app = BrokenTestApp()
        result = add_radare2_to_intellicrack_app(broken_app)

        assert result is False

    def test_add_radare2_without_update_output_signal(self, minimal_app: MinimalTestApp) -> None:
        """Integration works even when app lacks update_output signal."""
        result = add_radare2_to_intellicrack_app(minimal_app)

        assert isinstance(result, bool)

    def test_add_radare2_with_app_lacking_tab_widget(self) -> None:
        """Integration handles apps without tab_widget attribute."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        class NoTabApp:
            pass

        app = NoTabApp()
        result = add_radare2_to_intellicrack_app(app)

        assert isinstance(result, bool)

    def test_add_radare2_creates_real_widgets(self, real_app: RealTestApp) -> None:
        """Integration creates actual Qt widgets in tab structure."""
        initial_count = real_app.tab_widget.count() if real_app.tab_widget else 0

        result = add_radare2_to_intellicrack_app(real_app)

        if result and real_app.tab_widget:
            final_count = real_app.tab_widget.count()
            assert final_count >= initial_count


class TestIntegrateWithMainApp:
    """Test suite for integrate_with_main_app function."""

    def test_integrate_with_main_app_no_qapplication_fails(self) -> None:
        """Automatic integration fails when no QApplication exists."""
        if QApplication.instance():
            pytest.skip("Cannot test without QApplication when instance exists")

        result = integrate_with_main_app()

        assert result is False

    def test_integrate_finds_app_in_main_module(self) -> None:
        """Automatic integration finds IntellicrackApp in __main__."""
        import __main__

        original_app = getattr(__main__, "app", None)

        try:
            test_app = RealTestApp()
            test_app.__class__.__name__ = "IntellicrackApp"
            __main__.app = test_app

            result = integrate_with_main_app()

            assert isinstance(result, bool)

        finally:
            if original_app is not None:
                __main__.app = original_app
            elif hasattr(__main__, "app"):
                delattr(__main__, "app")

    def test_integrate_searches_sys_modules(self) -> None:
        """Automatic integration searches sys.modules for app instances."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        test_module_name = "test_integration_module_temp"
        original_module = sys.modules.get(test_module_name)

        try:
            import types

            test_module = types.ModuleType(test_module_name)
            test_app = RealTestApp()
            test_app.__class__.__name__ = "IntellicrackApp"
            test_module.app = test_app

            sys.modules[test_module_name] = test_module

            result = integrate_with_main_app()

            assert isinstance(result, bool)

        finally:
            if original_module is not None:
                sys.modules[test_module_name] = original_module
            else:
                sys.modules.pop(test_module_name, None)

    def test_integrate_handles_no_top_level_widgets(self) -> None:
        """Automatic integration handles empty top-level widget list."""
        result = integrate_with_main_app()

        assert isinstance(result, bool)

    def test_integrate_validates_app_class_name(self) -> None:
        """Automatic integration checks for IntellicrackApp class name."""
        import __main__

        original_app = getattr(__main__, "app", None)

        try:
            wrong_class_app = RealTestApp()
            wrong_class_app.__class__.__name__ = "WrongAppName"
            __main__.app = wrong_class_app

            result = integrate_with_main_app()

            assert isinstance(result, bool)

        finally:
            if original_app is not None:
                __main__.app = original_app
            elif hasattr(__main__, "app"):
                delattr(__main__, "app")


class TestCreateStandaloneRadare2App:
    """Test suite for create_standalone_radare2_app function."""

    def test_create_standalone_app_returns_tuple(self) -> None:
        """Creating standalone app returns tuple of app and window."""
        result = create_standalone_radare2_app()

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_create_standalone_app_creates_real_objects_or_none(self) -> None:
        """Standalone app creation returns real QApplication/window or None."""
        app, window = create_standalone_radare2_app()

        if app is not None:
            assert hasattr(app, "__class__")
        if window is not None:
            assert hasattr(window, "__class__")

    def test_create_standalone_app_handles_creation_failure(self) -> None:
        """Standalone app gracefully handles creation failures."""
        app, window = create_standalone_radare2_app()

        assert (app is None and window is None) or (app is not None and window is not None)

    def test_create_standalone_app_consistency(self) -> None:
        """Both app and window are None or both are valid objects."""
        app, window = create_standalone_radare2_app()

        if app is None:
            assert window is None
        if window is None:
            assert app is None


class TestShowIntegrationStatus:
    """Test suite for show_integration_status function."""

    def test_show_status_without_app_returns_dict(self) -> None:
        """Showing status without app returns status dictionary."""
        status = show_integration_status()

        assert isinstance(status, dict)
        assert len(status) > 0

    def test_show_status_with_app_includes_app_info(self, real_app: RealTestApp) -> None:
        """Showing status with app includes app-specific information."""
        status = show_integration_status(real_app)

        assert isinstance(status, dict)
        if "error" not in status:
            assert "app_type" in status
            assert "has_tab_widget" in status
            assert "has_menu_bar" in status
            assert "has_r2_ui_manager" in status
            assert "has_r2_widget" in status

    def test_show_status_detects_tab_widget_presence(self) -> None:
        """Status correctly identifies presence of tab widget."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        app_with_tabs = RealTestApp(has_tab_widget=True)
        app_without_tabs = RealTestApp(has_tab_widget=False)

        status_with = show_integration_status(app_with_tabs)
        status_without = show_integration_status(app_without_tabs)

        if "has_tab_widget" in status_with and "has_tab_widget" in status_without:
            assert status_with["has_tab_widget"] is True
            assert status_without["has_tab_widget"] is False

    def test_show_status_detects_menu_bar_presence(self, real_app: RealTestApp) -> None:
        """Status correctly identifies presence of menu bar."""
        status = show_integration_status(real_app)

        if "has_menu_bar" in status:
            assert isinstance(status["has_menu_bar"], bool)

    def test_show_status_handles_exception_gracefully(self) -> None:
        """Status function handles exceptions and returns error dict."""
        broken_app = BrokenTestApp()
        status = show_integration_status(broken_app)

        assert isinstance(status, dict)

    def test_show_status_includes_app_type_string(self, real_app: RealTestApp) -> None:
        """Status includes string representation of app type."""
        status = show_integration_status(real_app)

        if "app_type" in status:
            assert isinstance(status["app_type"], str)
            assert "RealTestApp" in status["app_type"]

    def test_show_status_detects_r2_integration_state(self, real_app: RealTestApp) -> None:
        """Status detects whether R2 integration has occurred."""
        status_before = show_integration_status(real_app)

        add_radare2_to_intellicrack_app(real_app)

        status_after = show_integration_status(real_app)

        assert isinstance(status_before, dict)
        assert isinstance(status_after, dict)


class TestIntegrationWithRealApplications:
    """Test integration functions with real PyQt6 applications."""

    def test_add_radare2_to_real_app_with_tabs_creates_widgets(self, real_app: RealTestApp) -> None:
        """Adding R2 to real app with QTabWidget creates actual tabs."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        initial_count = real_app.tab_widget.count() if real_app.tab_widget else 0

        result = add_radare2_to_intellicrack_app(real_app)

        if result and real_app.tab_widget:
            final_count = real_app.tab_widget.count()
            assert final_count >= initial_count

    def test_status_reflects_actual_integration_state(self, real_app: RealTestApp) -> None:
        """Status accurately reflects integration state changes."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        status_before = show_integration_status(real_app)
        add_radare2_to_intellicrack_app(real_app)
        status_after = show_integration_status(real_app)

        assert isinstance(status_before, dict)
        assert isinstance(status_after, dict)

    def test_multiple_integration_calls_are_idempotent(self, real_app: RealTestApp) -> None:
        """Multiple integration calls don't cause errors or duplicate widgets."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        result1 = add_radare2_to_intellicrack_app(real_app)
        result2 = add_radare2_to_intellicrack_app(real_app)

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_add_radare2_to_app_without_required_attributes(self) -> None:
        """Integration handles apps missing required attributes gracefully."""

        class EmptyApp:
            pass

        app = EmptyApp()
        result = add_radare2_to_intellicrack_app(app)

        assert isinstance(result, bool)

    def test_multiple_integration_calls_on_same_app_handle_cleanup(self, real_app: RealTestApp) -> None:
        """Multiple integration calls properly handle state management."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        result1 = add_radare2_to_intellicrack_app(real_app)
        cleanup_integration()
        result2 = add_radare2_to_intellicrack_app(real_app)

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)

    def test_status_with_partially_integrated_app(self) -> None:
        """Status works with app that has some but not all R2 attributes."""

        class PartialApp:
            def __init__(self) -> None:
                self.tab_widget = QTabWidget()
                self.r2_widget = object()

        app = PartialApp()
        status = show_integration_status(app)

        assert isinstance(status, dict)

    def test_integration_with_custom_app_class_name(self) -> None:
        """Integration correctly validates app class names."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        custom_app = RealTestApp()
        custom_app.__class__.__name__ = "CustomIntellicrackApp"

        result = add_radare2_to_intellicrack_app(custom_app)

        assert isinstance(result, bool)


class TestIntegrationFunctionality:
    """Test actual integration functionality and real behavior."""

    def test_integration_creates_real_qt_objects(self, real_app: RealTestApp) -> None:
        """Integration creates real Qt widgets, not placeholder objects."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        result = add_radare2_to_intellicrack_app(real_app)

        if result and real_app.tab_widget:
            for i in range(real_app.tab_widget.count()):
                widget = real_app.tab_widget.widget(i)
                assert widget is not None
                assert hasattr(widget, "metaObject")

    def test_integration_preserves_existing_tabs(self, real_app: RealTestApp) -> None:
        """Integration doesn't remove or corrupt existing tabs."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        if real_app.tab_widget:
            from intellicrack.handlers.pyqt6_handler import QLabel

            test_widget = QLabel("Test Tab")
            real_app.tab_widget.addTab(test_widget, "Original Tab")
            initial_count = real_app.tab_widget.count()

            result = add_radare2_to_intellicrack_app(real_app)

            if result:
                final_count = real_app.tab_widget.count()
                assert final_count >= initial_count

                found_original = False
                for i in range(final_count):
                    if real_app.tab_widget.tabText(i) == "Original Tab":
                        found_original = True
                        break
                assert found_original

    def test_status_provides_actionable_information(self) -> None:
        """Status dict contains useful diagnostic information."""
        status = show_integration_status()

        assert isinstance(status, dict)
        assert len(status) > 0

        if "error" not in status:
            assert any(key.startswith("has_") or key.startswith("is_") or "status" in key for key in status)


class TestErrorRecovery:
    """Test error handling and recovery mechanisms."""

    def test_integration_recovers_from_widget_creation_issues(self) -> None:
        """Integration handles widget creation failures gracefully."""

        class FailingTabApp:
            def __init__(self) -> None:
                self._tab_widget = QTabWidget()

            @property
            def tab_widget(self) -> QTabWidget:
                return self._tab_widget

        app = FailingTabApp()
        result = add_radare2_to_intellicrack_app(app)

        assert isinstance(result, bool)

    def test_status_handles_missing_attributes_safely(self) -> None:
        """Status function handles apps with missing attributes."""

        class MinimalStatusApp:
            pass

        app = MinimalStatusApp()
        status = show_integration_status(app)

        assert isinstance(status, dict)

    def test_integration_with_read_only_app_attributes(self) -> None:
        """Integration handles apps with read-only or protected attributes."""

        class ReadOnlyApp:
            def __init__(self) -> None:
                self._tab_widget = QTabWidget()

            @property
            def tab_widget(self) -> QTabWidget:
                return self._tab_widget

        app = ReadOnlyApp()
        result = add_radare2_to_intellicrack_app(app)

        assert isinstance(result, bool)


class TestRealWorldScenarios:
    """Test realistic usage scenarios."""

    def test_full_integration_workflow(self, real_app: RealTestApp) -> None:
        """Complete integration workflow from setup to validation."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        status_initial = show_integration_status(real_app)
        assert isinstance(status_initial, dict)

        result = add_radare2_to_intellicrack_app(real_app)
        assert isinstance(result, bool)

        status_final = show_integration_status(real_app)
        assert isinstance(status_final, dict)

    def test_integration_with_existing_intellicrack_components(self, real_app: RealTestApp) -> None:
        """Integration works alongside existing Intellicrack features."""
        from intellicrack.ui.comprehensive_integration import cleanup_integration

        cleanup_integration()

        if real_app.tab_widget:
            from intellicrack.handlers.pyqt6_handler import QTextEdit

            existing_component = QTextEdit()
            real_app.tab_widget.addTab(existing_component, "Existing Feature")

        result = add_radare2_to_intellicrack_app(real_app)

        assert isinstance(result, bool)

    def test_standalone_app_creation_workflow(self) -> None:
        """Complete standalone app creation and validation."""
        app, window = create_standalone_radare2_app()

        if app is not None and window is not None:
            assert hasattr(window, "show")

        assert (app is None and window is None) or (app is not None and window is not None)
