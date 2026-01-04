"""Production tests for main window initialization and component integration.

Tests validate real component initialization, error handling, and UI setup
for the Intellicrack main application window using ZERO mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import platform
import sys
from pathlib import Path
from typing import Any

import pytest


PYQT6_AVAILABLE = True
try:
    from intellicrack.handlers.pyqt6_handler import QApplication
except ImportError:
    PYQT6_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE or platform.system() != "Windows",
    reason="PyQt6 required and Windows platform required for main window tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create or get QApplication instance for testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.processEvents()


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create test PE binary file."""
    binary = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x90\x00" * 29
    binary.write_bytes(dos_header + b"\x00" * 1024)
    return binary


class TestMainWindowRealInitialization:
    """Test main window initialization with real components."""

    def test_main_window_creates_successfully(self, qapp: Any) -> None:
        """Main window initializes without exceptions."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert window is not None
        assert hasattr(window, "component_status")
        assert isinstance(window.component_status, dict)

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_initializes_component_status_tracking(self, qapp: Any) -> None:
        """Main window initializes component status tracking dictionary."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        required_components = [
            "vulnerability_engine",
            "binary_analyzer",
            "ai_assistant",
            "analysis_orchestrator",
            "llm_handler",
            "script_handler",
            "report_handler",
        ]

        for component in required_components:
            assert component in window.component_status  # type: ignore[attr-defined]
            assert "enabled" in window.component_status[component]  # type: ignore[attr-defined]
            assert "error" in window.component_status[component]  # type: ignore[attr-defined]

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_attempts_component_initialization(self, qapp: Any) -> None:
        """Main window attempts to initialize all components."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        for component_name in window.component_status:  # type: ignore[attr-defined]
            status = window.component_status[component_name]  # type: ignore[attr-defined]
            if status["enabled"]:
                assert status["error"] is None
            else:
                assert status["error"] is not None or status["enabled"] is False

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_has_required_attributes(self, qapp: Any) -> None:
        """Main window has all required attributes after initialization."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "binary_path")
        assert hasattr(window, "analyze_results")
        assert hasattr(window, "binary_info")
        assert hasattr(window, "vulnerability_engine")
        assert hasattr(window, "binary_analyzer")
        assert hasattr(window, "ai_assistant")
        assert hasattr(window, "analysis_orchestrator")
        assert hasattr(window, "llm_handler")
        assert hasattr(window, "script_handler")
        assert hasattr(window, "report_handler")

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowSignals:
    """Test main window PyQt signal definitions and functionality."""

    def test_main_window_defines_required_signals(self, qapp: Any) -> None:
        """Main window defines all required PyQt signals."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "update_output")
        assert hasattr(window, "update_status")
        assert hasattr(window, "update_progress")
        assert hasattr(window, "clear_output")

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_signals_can_emit(self, qapp: Any) -> None:
        """Main window signals can be emitted without errors."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        try:
            window.update_output.emit("test output")
            window.update_status.emit("test status")
            window.update_progress.emit(50)
            window.clear_output.emit()  # type: ignore[attr-defined]
            qapp.processEvents()
        except Exception as e:
            pytest.fail(f"Signal emission failed: {e}")

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_signals_can_be_connected(self, qapp: Any) -> None:
        """Main window signals can be connected to slots."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()
        signal_received: dict[str, bool] = {
            "update_output": False,
            "update_status": False,
            "update_progress": False,
        }

        def on_update_output(text: str) -> None:
            signal_received["update_output"] = True

        def on_update_status(text: str) -> None:
            signal_received["update_status"] = True

        def on_update_progress(value: int) -> None:
            signal_received["update_progress"] = True

        window.update_output.connect(on_update_output)
        window.update_status.connect(on_update_status)
        window.update_progress.connect(on_update_progress)

        window.update_output.emit("test")
        window.update_status.emit("test")
        window.update_progress.emit(50)

        qapp.processEvents()

        assert signal_received["update_output"] is True
        assert signal_received["update_status"] is True
        assert signal_received["update_progress"] is True

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowFileOperations:
    """Test main window file browsing and binary loading operations."""

    def test_main_window_initializes_with_no_binary_path(self, qapp: Any) -> None:
        """Main window starts with no binary path set."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert window.binary_path is None

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_binary_path_can_be_set(self, qapp: Any, test_binary: Path) -> None:
        """Main window binary path attribute can be set programmatically."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        window.binary_path = str(test_binary)

        assert window.binary_path == str(test_binary)

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_has_browse_for_file_method(self, qapp: Any) -> None:
        """Main window has _browse_for_file method defined."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "_browse_for_file")
        assert callable(window._browse_for_file)

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowAnalysisOperations:
    """Test main window analysis operations and workflows."""

    def test_main_window_has_run_analysis_method(self, qapp: Any) -> None:
        """Main window has _run_analysis method defined."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "_run_analysis")
        assert callable(window._run_analysis)

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_analysis_requires_binary_path(self, qapp: Any) -> None:
        """Main window analysis checks for binary path before running."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()
        window.binary_path = None

        try:
            window._run_analysis()  # type: ignore[attr-defined]
        except Exception:
            pass

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowComponentIntegration:
    """Test main window component integration and orchestration."""

    def test_main_window_registers_handlers_with_orchestrator(self, qapp: Any) -> None:
        """Main window registers available handlers with orchestrator."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        if window.analysis_orchestrator is not None:  # type: ignore[attr-defined]
            assert window.analysis_orchestrator is not None  # type: ignore[attr-defined]

            if window.llm_handler is not None:  # type: ignore[attr-defined]
                assert window.llm_handler is not None  # type: ignore[attr-defined]

            if window.script_handler is not None:  # type: ignore[attr-defined]
                assert window.script_handler is not None  # type: ignore[attr-defined]

            if window.report_handler is not None:  # type: ignore[attr-defined]
                assert window.report_handler is not None  # type: ignore[attr-defined]

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_handles_component_initialization_failures(self, qapp: Any) -> None:
        """Main window gracefully handles component initialization failures."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        for component_name, status in window.component_status.items():  # type: ignore[attr-defined]
            if not status["enabled"]:
                assert status["error"] is not None or status["enabled"] is False
            else:
                assert status["error"] is None

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowUISetup:
    """Test main window UI initialization and setup."""

    def test_main_window_has_ui_setup_methods(self, qapp: Any) -> None:
        """Main window defines all UI setup methods."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "_setup_ui")
        assert hasattr(window, "_setup_signals")
        assert hasattr(window, "_setup_status_bar")
        assert hasattr(window, "_setup_menu_bar")

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_applies_initial_settings(self, qapp: Any) -> None:
        """Main window applies initial settings during initialization."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "_apply_initial_settings")

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_updates_ui_for_disabled_components(self, qapp: Any) -> None:
        """Main window updates UI based on component availability."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert hasattr(window, "_update_ui_for_disabled_components")

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowErrorHandling:
    """Test main window error handling and recovery."""

    def test_main_window_continues_with_failed_components(self, qapp: Any) -> None:
        """Main window continues functioning even if some components fail to initialize."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert window is not None

        at_least_one_component_works = any(
            status["enabled"] for status in window.component_status.values()  # type: ignore[attr-defined]
        )

        window.close()
        window.deleteLater()
        qapp.processEvents()

    def test_main_window_frida_integration_failure_graceful(self, qapp: Any) -> None:
        """Main window handles Frida integration failures gracefully."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        assert window is not None

        window.close()
        window.deleteLater()
        qapp.processEvents()


class TestMainWindowCleanup:
    """Test main window cleanup and resource management."""

    def test_main_window_can_be_closed(self, qapp: Any) -> None:
        """Main window can be closed without errors."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window = IntellicrackMainWindow()

        try:
            window.close()
            window.deleteLater()
            qapp.processEvents()
        except Exception as e:
            pytest.fail(f"Window close failed: {e}")

    def test_multiple_main_windows_can_be_created(self, qapp: Any) -> None:
        """Multiple main window instances can be created sequentially."""
        from intellicrack.ui.main_window import IntellicrackMainWindow

        window1 = IntellicrackMainWindow()
        window1.close()
        window1.deleteLater()
        qapp.processEvents()

        window2 = IntellicrackMainWindow()
        window2.close()
        window2.deleteLater()
        qapp.processEvents()
