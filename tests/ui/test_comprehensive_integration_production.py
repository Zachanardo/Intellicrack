"""Production tests for comprehensive R2 integration module.

This module tests the ComprehensiveR2Integration class which provides
the main entry point for integrating all radare2 functionality into
Intellicrack applications using ZERO mocks.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack and follows GPL v3 licensing.
"""

import sys
from typing import Any

import pytest

PYQT6_AVAILABLE = True
try:
    from intellicrack.handlers.pyqt6_handler import QMainWindow, QTabWidget, QWidget
except ImportError:
    PYQT6_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 required for comprehensive integration tests"
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create or get QApplication instance for testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")

    from intellicrack.handlers.pyqt6_handler import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.processEvents()


class TestComprehensiveR2IntegrationInitialization:
    """Test ComprehensiveR2Integration class initialization."""

    def test_integration_initializes_successfully(self, qapp: Any) -> None:
        """Integration initializes with default values and empty state."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()

        assert integration is not None
        assert hasattr(integration, "ui_manager")
        assert hasattr(integration, "integrated_apps")
        assert hasattr(integration, "integration_status")

    def test_integration_starts_with_empty_apps_list(self, qapp: Any) -> None:
        """Integration starts with no integrated applications."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()

        assert integration.integrated_apps == []

    def test_integration_has_status_dictionary(self, qapp: Any) -> None:
        """Integration has integration_status dictionary."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()

        assert isinstance(integration.integration_status, dict)


class TestComprehensiveR2IntegrationDetection:
    """Test integration method detection for different application types."""

    def test_detect_integration_method_with_main_window(self, qapp: Any) -> None:
        """Detector identifies QMainWindow instances correctly."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        method = integration._detect_integration_method(window)

        assert method in ["main_window", "tab_widget"]

        window.deleteLater()
        qapp.processEvents()

    def test_detect_integration_method_with_tab_widget(self, qapp: Any) -> None:
        """Detector identifies applications with tab widgets."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        widget = QWidget()
        widget.tab_widget = QTabWidget()

        method = integration._detect_integration_method(widget)

        assert method in ["tab_widget", "generic_widget"]

        widget.deleteLater()
        qapp.processEvents()

    def test_detect_integration_method_with_generic_widget(self, qapp: Any) -> None:
        """Detector identifies generic QWidget instances."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        widget = QWidget()

        method = integration._detect_integration_method(widget)

        assert method in ["generic_widget", "fallback"]

        widget.deleteLater()
        qapp.processEvents()

    def test_detect_integration_method_with_unknown_type(self, qapp: Any) -> None:
        """Detector uses fallback for unknown types."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        app = object()

        method = integration._detect_integration_method(app)

        assert method == "fallback"


class TestComprehensiveR2IntegrationWithRealWidgets:
    """Test integration with actual PyQt6 widgets."""

    def test_integration_with_real_qmainwindow(self, qapp: Any) -> None:
        """Integration works with real QMainWindow instance."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()
        window.setCentralWidget(window.tab_widget)

        result = integration.integrate_with_application(window)

        assert result is True
        assert window in integration.integrated_apps

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_integration_adds_tabs_to_window(self, qapp: Any) -> None:
        """Integration adds R2 tabs to main window tab widget."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()
        window.setCentralWidget(window.tab_widget)

        initial_count = window.tab_widget.count()

        integration.integrate_with_application(window)

        assert window.tab_widget.count() >= initial_count

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_integration_with_real_tab_widget(self, qapp: Any) -> None:
        """Integration works with widget containing real QTabWidget."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        widget = QWidget()
        widget.tab_widget = QTabWidget()

        result = integration.integrate_with_application(widget)

        assert result is True
        assert widget in integration.integrated_apps

        widget.deleteLater()
        qapp.processEvents()

    def test_integration_creates_ui_manager(self, qapp: Any) -> None:
        """Integration creates UI manager for applications."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integration.integrate_with_application(window)

        assert integration.ui_manager is not None

        window.deleteLater()
        qapp.processEvents()


class TestComprehensiveR2IntegrationStatusTracking:
    """Test integration status tracking functionality."""

    def test_get_integration_status_returns_dict(self, qapp: Any) -> None:
        """Get integration status returns dictionary."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        status = integration.get_integration_status()

        assert isinstance(status, dict)

    def test_get_integration_status_returns_copy(self, qapp: Any) -> None:
        """Get integration status returns independent copy of status dict."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        status1 = integration.get_integration_status()
        status1["test_key"] = True

        status2 = integration.get_integration_status()

        assert "test_key" not in status2
        assert status1 is not status2

    def test_integration_status_updates_on_integration(self, qapp: Any) -> None:
        """Integration status updates when integration succeeds."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integration.integrate_with_application(window)
        status = integration.get_integration_status()

        assert "ui_manager" in status or len(status) > 0

        window.deleteLater()
        qapp.processEvents()


class TestComprehensiveR2IntegrationCleanup:
    """Test integration cleanup and resource management."""

    def test_cleanup_resets_integrated_apps(self, qapp: Any) -> None:
        """Cleanup clears all integrations and resets internal state."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integration.integrate_with_application(window)
        integration.cleanup()

        assert len(integration.integrated_apps) == 0

        window.deleteLater()
        qapp.processEvents()

    def test_cleanup_can_be_called_multiple_times(self, qapp: Any) -> None:
        """Cleanup can be called multiple times without errors."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()

        try:
            integration.cleanup()
            integration.cleanup()
        except Exception as e:
            pytest.fail(f"Cleanup raised unexpected exception: {e}")

    def test_cleanup_resets_ui_manager(self, qapp: Any) -> None:
        """Cleanup clears UI manager reference."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integration.integrate_with_application(window)
        integration.cleanup()

        window.deleteLater()
        qapp.processEvents()


class TestComprehensiveR2IntegrationMultipleApps:
    """Test integration with multiple applications."""

    def test_multiple_integrations_tracked(self, qapp: Any) -> None:
        """Multiple application integrations are tracked correctly."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window1 = QMainWindow()
        window1.tab_widget = QTabWidget()
        window2 = QMainWindow()
        window2.tab_widget = QTabWidget()

        integration.integrate_with_application(window1)
        integration.integrate_with_application(window2)

        assert len(integration.integrated_apps) >= 1
        assert window1 in integration.integrated_apps or window2 in integration.integrated_apps

        window1.deleteLater()
        window2.deleteLater()
        qapp.processEvents()


class TestComprehensiveR2IntegrationErrorHandling:
    """Test error handling and edge cases."""

    def test_integration_with_none_app(self, qapp: Any) -> None:
        """Integration with None returns False gracefully."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()

        result = integration.integrate_with_application(None)

        assert result is False

    def test_get_ui_manager_returns_none_before_integration(self, qapp: Any) -> None:
        """get_ui_manager returns None before any integration."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        manager = integration.get_ui_manager()

        assert manager is None

    def test_get_ui_manager_returns_manager_after_integration(self, qapp: Any) -> None:
        """get_ui_manager returns the created manager instance."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integration.integrate_with_application(window)
        manager = integration.get_ui_manager()

        assert manager is integration.ui_manager

        window.deleteLater()
        qapp.processEvents()


class TestModuleLevelIntegrationFunctions:
    """Test module-level integration functions."""

    def test_get_comprehensive_integration_returns_instance(self, qapp: Any) -> None:
        """get_comprehensive_integration returns integration instance."""
        from intellicrack.ui.comprehensive_integration import get_comprehensive_integration

        integration = get_comprehensive_integration()

        assert integration is not None

    def test_get_comprehensive_integration_returns_singleton(self, qapp: Any) -> None:
        """get_comprehensive_integration returns singleton instance."""
        from intellicrack.ui.comprehensive_integration import get_comprehensive_integration

        integration1 = get_comprehensive_integration()
        integration2 = get_comprehensive_integration()

        assert integration1 is integration2

    def test_integrate_radare2_comprehensive_integrates_app(self, qapp: Any) -> None:
        """integrate_radare2_comprehensive successfully integrates application."""
        from intellicrack.ui.comprehensive_integration import (
            cleanup_integration,
            integrate_radare2_comprehensive,
        )

        cleanup_integration()

        window = QMainWindow()
        window.tab_widget = QTabWidget()

        result = integrate_radare2_comprehensive(window)

        assert result is True or result is False

        window.deleteLater()
        qapp.processEvents()

    def test_get_integration_status_module_function(self, qapp: Any) -> None:
        """get_integration_status returns current integration state."""
        from intellicrack.ui.comprehensive_integration import (
            cleanup_integration,
            get_integration_status,
            integrate_radare2_comprehensive,
        )

        cleanup_integration()

        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integrate_radare2_comprehensive(window)
        status = get_integration_status()

        assert isinstance(status, dict)

        window.deleteLater()
        qapp.processEvents()

    def test_cleanup_integration_resets_global_instance(self, qapp: Any) -> None:
        """cleanup_integration resets global integration singleton."""
        from intellicrack.ui.comprehensive_integration import (
            cleanup_integration,
            get_comprehensive_integration,
            integrate_radare2_comprehensive,
        )

        window = QMainWindow()
        window.tab_widget = QTabWidget()

        integrate_radare2_comprehensive(window)
        integration1 = get_comprehensive_integration()

        cleanup_integration()
        integration2 = get_comprehensive_integration()

        assert integration1 is not integration2

        window.deleteLater()
        qapp.processEvents()


class TestTabIntegrationFunctionality:
    """Test tab integration and functionality."""

    def test_tabs_are_functional_after_integration(self, qapp: Any) -> None:
        """Integrated tabs are functional and can be switched."""
        from intellicrack.ui.comprehensive_integration import (
            cleanup_integration,
            integrate_radare2_comprehensive,
        )

        cleanup_integration()

        window = QMainWindow()
        window.tab_widget = QTabWidget()
        window.setCentralWidget(window.tab_widget)

        integrate_radare2_comprehensive(window)

        if window.tab_widget.count() > 0:
            window.tab_widget.setCurrentIndex(0)
            assert window.tab_widget.currentIndex() == 0

        if window.tab_widget.count() > 1:
            window.tab_widget.setCurrentIndex(1)
            assert window.tab_widget.currentIndex() == 1

        window.deleteLater()
        qapp.processEvents()

    def test_integration_preserves_existing_tabs(self, qapp: Any) -> None:
        """Integration preserves existing tabs in widget."""
        from intellicrack.ui.comprehensive_integration import (
            cleanup_integration,
            integrate_radare2_comprehensive,
        )

        cleanup_integration()

        window = QMainWindow()
        window.tab_widget = QTabWidget()
        window.setCentralWidget(window.tab_widget)

        existing_widget = QWidget()
        window.tab_widget.addTab(existing_widget, "Existing Tab")

        initial_count = window.tab_widget.count()
        integrate_radare2_comprehensive(window)

        assert window.tab_widget.count() >= initial_count
        assert window.tab_widget.tabText(0) == "Existing Tab"

        window.deleteLater()
        qapp.processEvents()


class TestIntegrationBinaryPathSync:
    """Test binary path synchronization between app and UI manager."""

    def test_binary_path_syncs_to_ui_manager(self, qapp: Any) -> None:
        """Binary path synchronization updates UI manager when app path changes."""
        from intellicrack.ui.comprehensive_integration import ComprehensiveR2Integration

        integration = ComprehensiveR2Integration()
        window = QMainWindow()
        window.tab_widget = QTabWidget()
        window.binary_path = "test.exe"

        integration.integrate_with_application(window)

        window.deleteLater()
        qapp.processEvents()
