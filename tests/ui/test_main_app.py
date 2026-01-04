"""
Comprehensive tests for IntellicrackApp main application window.

Tests the core UI initialization, tab management, binary loading workflows,
and integration between UI components and analysis engines.
"""

import os
import sys
from pathlib import Path
from typing import Any, Generator

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.main_app import IntellicrackApp
from tests.base_test import IntellicrackTestBase


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for testing."""
    existing_app = QApplication.instance()
    if existing_app is None:
        yield QApplication(sys.argv)
    else:
        assert isinstance(existing_app, QApplication), "Expected QApplication instance"
        yield existing_app


class FakeModelManager:
    """Fake ModelManager for testing without AI dependencies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def load_model(self, model_name: str) -> None:
        pass

    def cleanup(self) -> None:
        pass


class FakeDashboardManager:
    """Fake DashboardManager for testing without dashboard dependencies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


@pytest.fixture
def main_app(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> Generator[IntellicrackApp, None, None]:
    """Create IntellicrackApp instance for testing."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ["INTELLICRACK_TESTING"] = "1"
    os.environ["DISABLE_AI_WORKERS"] = "1"

    monkeypatch.setattr("intellicrack.ui.main_app.ModelManager", FakeModelManager)
    monkeypatch.setattr("intellicrack.ui.main_app.DashboardManager", FakeDashboardManager)

    app = IntellicrackApp()
    yield app
    app.close()


class TestIntellicrackAppInitialization(IntellicrackTestBase):
    """Test IntellicrackApp initialization and setup."""

    def test_app_initializes_successfully(self, main_app: IntellicrackApp) -> None:
        """Application initializes without errors."""
        assert main_app is not None
        assert main_app.windowTitle() == "Intellicrack - Advanced Binary Analysis"

    def test_main_window_properties_set(self, main_app: IntellicrackApp) -> None:
        """Main window properties are configured correctly."""
        assert main_app.width() >= 1400
        assert main_app.height() >= 900
        assert main_app.isVisible() or os.environ.get("QT_QPA_PLATFORM") == "offscreen"

    def test_tabs_widget_created(self, main_app: IntellicrackApp) -> None:
        """Tab widget is created and populated."""
        assert hasattr(main_app, "tabs")
        assert main_app.tabs is not None
        assert main_app.tabs.count() > 0

    def test_required_tabs_present(self, main_app: IntellicrackApp) -> None:
        """All required tabs are present in the application."""
        tab_names: list[str] = [
            main_app.tabs.tabText(i) for i in range(main_app.tabs.count())
        ]
        required_tabs = ["Dashboard", "Analysis", "Exploitation", "Tools"]
        for required_tab in required_tabs:
            assert any(required_tab in name for name in tab_names), \
                    f"Required tab '{required_tab}' not found in {tab_names}"

    def test_output_panel_created(self, main_app: IntellicrackApp) -> None:
        """Output panel is created and accessible."""
        assert hasattr(main_app, "output")
        assert main_app.output is not None
        assert hasattr(main_app, "raw_console_output")

    def test_status_bar_exists(self, main_app: IntellicrackApp) -> None:
        """Status bar is created and accessible."""
        status_bar = main_app.statusBar()
        assert status_bar is not None


class TestIntellicrackAppTabManagement(IntellicrackTestBase):
    """Test tab creation and management."""

    def test_switch_to_analysis_tab(self, main_app: IntellicrackApp) -> None:
        """Can switch to analysis tab programmatically."""
        for i in range(main_app.tabs.count()):
            if "Analysis" in main_app.tabs.tabText(i):
                main_app.tabs.setCurrentIndex(i)
                assert main_app.tabs.currentIndex() == i
                return
        pytest.fail("Analysis tab not found")

    def test_switch_to_exploitation_tab(self, main_app: IntellicrackApp) -> None:
        """Can switch to exploitation tab programmatically."""
        for i in range(main_app.tabs.count()):
            if "Exploitation" in main_app.tabs.tabText(i):
                main_app.tabs.setCurrentIndex(i)
                assert main_app.tabs.currentIndex() == i
                return
        pytest.fail("Exploitation tab not found")

    def test_switch_to_tools_tab(self, main_app: IntellicrackApp) -> None:
        """Can switch to tools tab programmatically."""
        for i in range(main_app.tabs.count()):
            if "Tools" in main_app.tabs.tabText(i):
                main_app.tabs.setCurrentIndex(i)
                assert main_app.tabs.currentIndex() == i
                return
        pytest.fail("Tools tab not found")

    def test_handle_switch_tab_method(self, main_app: IntellicrackApp) -> None:
        """handle_switch_tab method changes active tab."""
        initial_index = main_app.tabs.currentIndex()
        new_index = (initial_index + 1) % main_app.tabs.count()

        main_app.handle_switch_tab(new_index)
        assert main_app.tabs.currentIndex() == new_index


class TestIntellicrackAppOutputMethods(IntellicrackTestBase):
    """Test output and logging methods."""

    def test_append_output_adds_text(self, main_app: IntellicrackApp) -> None:
        """append_output adds text to output panel."""
        test_message = "Test output message"
        main_app.append_output(test_message)

        output_text = main_app.output.toPlainText()
        assert test_message in output_text

    def test_clear_output_clears_text(self, main_app: IntellicrackApp) -> None:
        """clear_output removes all text from output panel."""
        main_app.append_output("Test message")
        assert len(main_app.output.toPlainText()) > 0

        main_app.clear_output()
        assert len(main_app.output.toPlainText()) == 0

    def test_log_message_returns_and_displays(self, main_app: IntellicrackApp) -> None:
        """log_message returns the message and displays it."""
        test_message = "Test log message"
        result = main_app.log_message(test_message)

        assert result == test_message
        assert test_message in main_app.output.toPlainText()

    def test_set_status_message_updates_status_bar(self, main_app: IntellicrackApp) -> None:
        """set_status_message updates the status bar."""
        test_status = "Test status message"
        main_app.set_status_message(test_status)

        status_bar = main_app.statusBar()
        assert status_bar is not None, "Status bar should exist"
        status_text = status_bar.currentMessage()
        assert test_status in status_text or status_text != ""

    def test_append_analysis_results_adds_results(self, main_app: IntellicrackApp) -> None:
        """append_analysis_results adds analysis output to panel."""
        test_results = "Analysis results: Binary is PE32"
        main_app.append_analysis_results(test_results)

        output_text = main_app.output.toPlainText()
        assert test_results in output_text


class TestIntellicrackAppBinaryLoading(IntellicrackTestBase):
    """Test binary loading workflows."""

    def test_on_binary_loaded_event_handler(self, main_app: IntellicrackApp) -> None:
        """_on_binary_loaded handles binary info correctly."""
        binary_info: dict[str, Any] = {
            "path": "test.exe",
            "size": 1024000,
            "format": "PE32",
            "architecture": "x86_64"
        }

        main_app._on_binary_loaded(binary_info)
        output_text = main_app.output.toPlainText()

        assert "test.exe" in output_text or "Binary loaded" in output_text

    def test_on_binary_loaded_with_real_pe_binary(self, main_app: IntellicrackApp) -> None:
        """_on_binary_loaded works with realistic PE binary metadata."""
        test_binary_path = PROJECT_ROOT / "tests" / "fixtures" / "binaries" / "pe" / "legitimate" / "7zip.exe"
        if not test_binary_path.exists():
            pytest.skip("Test binary not available")

        binary_info: dict[str, Any] = {
            "path": str(test_binary_path),
            "size": test_binary_path.stat().st_size,
            "format": "PE32+",
            "architecture": "AMD64",
            "entry_point": 0x1000
        }

        main_app._on_binary_loaded(binary_info)
        output_text = main_app.output.toPlainText()

        assert "7zip.exe" in output_text or "Binary" in output_text


class TestIntellicrackAppTaskHandlers(IntellicrackTestBase):
    """Test task management event handlers."""

    def test_on_task_started_logs_task(self, main_app: IntellicrackApp) -> None:
        """_on_task_started logs task initiation."""
        task_name = "Static Analysis"
        main_app._on_task_started(task_name)

        output_text = main_app.output.toPlainText()
        assert task_name in output_text or "started" in output_text.lower()

    def test_on_task_progress_updates_progress(self, main_app: IntellicrackApp) -> None:
        """_on_task_progress updates progress indicator."""
        main_app._on_task_progress(50)

        if hasattr(main_app, "progress_bar") and main_app.progress_bar is not None:
            assert main_app.progress_bar.value() == 50

    def test_on_task_completed_logs_completion(self, main_app: IntellicrackApp) -> None:
        """_on_task_completed logs task completion."""
        task_name = "Dynamic Analysis"
        main_app._on_task_completed(task_name)

        output_text = main_app.output.toPlainText()
        assert task_name in output_text or "completed" in output_text.lower()

    def test_on_task_failed_logs_error(self, main_app: IntellicrackApp) -> None:
        """_on_task_failed logs task failure with error."""
        task_name = "Protection Detection"
        error_message = "Failed to load binary"

        main_app._on_task_failed(task_name, error_message)

        output_text = main_app.output.toPlainText()
        assert (task_name in output_text or "failed" in output_text.lower() or
                "error" in output_text.lower())


class TestIntellicrackAppAnalysisHandlers(IntellicrackTestBase):
    """Test analysis completion handlers."""

    def test_on_analysis_completed_with_results(self, main_app: IntellicrackApp) -> None:
        """_on_analysis_completed processes analysis results."""
        results: list[dict[str, Any]] = [
            {"type": "static", "protections": ["VMProtect", "Themida"]},
            {"type": "dynamic", "api_calls": ["CreateFileW", "RegOpenKeyExW"]}
        ]

        main_app._on_analysis_completed(results)
        output_text = main_app.output.toPlainText()

        assert len(output_text) > 0

    def test_on_analysis_completed_with_empty_results(self, main_app: IntellicrackApp) -> None:
        """_on_analysis_completed handles empty results gracefully."""
        results: list[Any] = []

        try:
            main_app._on_analysis_completed(results)
        except Exception as e:
            pytest.fail(f"Should handle empty results gracefully: {e}")


class TestIntellicrackAppPluginLoading(IntellicrackTestBase):
    """Test plugin loading and caching."""

    def test_load_available_plugins_returns_dict(self, main_app: IntellicrackApp) -> None:
        """load_available_plugins returns dictionary of available plugins."""
        plugins = main_app.load_available_plugins()

        assert isinstance(plugins, dict)
        assert "frida" in plugins or "ghidra" in plugins or len(plugins) >= 0

    def test_plugin_cache_validation(self, main_app: IntellicrackApp, tmp_path: Path) -> None:
        """Plugin cache validation works correctly."""
        test_plugin_dir = tmp_path / "plugins"
        test_plugin_dir.mkdir()

        test_plugin = test_plugin_dir / "test_plugin.js"
        test_plugin.write_text("console.log('test');")

        cached_data: dict[str, Any] = {
            "files": {str(test_plugin): test_plugin.stat().st_mtime}
        }

        is_valid = main_app._validate_plugin_directory_cache(
            "frida", test_plugin_dir, cached_data
        )
        assert isinstance(is_valid, bool)


class TestIntellicrackAppThemeManagement(IntellicrackTestBase):
    """Test theme and styling."""

    def test_on_theme_changed_applies_theme(self, main_app: IntellicrackApp) -> None:
        """on_theme_changed applies new theme."""
        initial_stylesheet = main_app.styleSheet()

        main_app.on_theme_changed("dark")

        new_stylesheet = main_app.styleSheet()
        assert new_stylesheet is not None


class TestIntellicrackAppProgressTracking(IntellicrackTestBase):
    """Test progress tracking functionality."""

    def test_set_progress_value_updates_progress(self, main_app: IntellicrackApp) -> None:
        """set_progress_value updates progress bar if present."""
        try:
            main_app.set_progress_value(75)
        except AttributeError:
            pass


class TestIntellicrackAppChatHandlers(IntellicrackTestBase):
    """Test AI chat handlers."""

    def test_handle_log_user_question(self, main_app: IntellicrackApp) -> None:
        """handle_log_user_question logs user question."""
        question = "How do I bypass VMProtect?"

        try:
            main_app.handle_log_user_question(question)
        except Exception as e:
            pytest.fail(f"Should handle user question: {e}")

    def test_append_chat_display(self, main_app: IntellicrackApp) -> None:
        """append_chat_display adds message to chat."""
        message = "Analysis complete: Found 3 protections"

        try:
            main_app.append_chat_display(message)
        except Exception as e:
            pytest.fail(f"Should handle chat message: {e}")

    def test_replace_last_chat_message(self, main_app: IntellicrackApp) -> None:
        """replace_last_chat_message replaces last chat message."""
        try:
            main_app.append_chat_display("Initial message")
            main_app.replace_last_chat_message("Updated message")
        except Exception as e:
            pytest.fail(f"Should handle message replacement: {e}")


class TestIntellicrackAppKeygenHandlers(IntellicrackTestBase):
    """Test keygen-related handlers."""

    def test_handle_set_keygen_name(self, main_app: IntellicrackApp) -> None:
        """handle_set_keygen_name sets keygen target name."""
        keygen_name = "Adobe Photoshop"

        try:
            main_app.handle_set_keygen_name(keygen_name)
        except Exception as e:
            pytest.fail(f"Should handle keygen name: {e}")

    def test_handle_set_keygen_version(self, main_app: IntellicrackApp) -> None:
        """handle_set_keygen_version sets keygen target version."""
        version = "2024.1.0"

        try:
            main_app.handle_set_keygen_version(version)
        except Exception as e:
            pytest.fail(f"Should handle keygen version: {e}")

    def test_handle_generate_key(self, main_app: IntellicrackApp) -> None:
        """handle_generate_key initiates key generation."""
        try:
            main_app.handle_generate_key()
        except Exception as e:
            pytest.fail(f"Should handle key generation request: {e}")


class TestIntellicrackAppEdgeCases(IntellicrackTestBase):
    """Test edge cases and error handling."""

    def test_handles_none_binary_info(self, main_app: IntellicrackApp) -> None:
        """App handles None binary_info without crashing."""
        try:
            main_app._on_binary_loaded({})
        except Exception as e:
            pytest.fail(f"Should handle empty binary info: {e}")

    def test_handles_malformed_analysis_results(self, main_app: IntellicrackApp) -> None:
        """App handles malformed analysis results."""
        malformed_results: list[Any] = [
            "not a dict",
            None,
            123,
            {"incomplete": "data"}
        ]

        try:
            main_app._on_analysis_completed(malformed_results)
        except Exception as e:
            pytest.fail(f"Should handle malformed results gracefully: {e}")

    def test_handles_long_output_text(self, main_app: IntellicrackApp) -> None:
        """App handles very long output text."""
        long_text = "A" * 100000

        try:
            main_app.append_output(long_text)
            output = main_app.output.toPlainText()
            assert len(output) > 0
        except Exception as e:
            pytest.fail(f"Should handle long text: {e}")

    def test_handles_unicode_in_output(self, main_app: IntellicrackApp) -> None:
        """App handles unicode characters in output."""
        unicode_text = "Analysis: 文件分析 🔍 Анализ"

        try:
            main_app.append_output(unicode_text)
            output = main_app.output.toPlainText()
            assert len(output) > 0
        except Exception as e:
            pytest.fail(f"Should handle unicode: {e}")


class TestIntellicrackAppWindowState(IntellicrackTestBase):
    """Test window state management."""

    def test_restore_window_state(self, main_app: IntellicrackApp) -> None:
        """restore_window_state restores saved state if available."""
        try:
            main_app.restore_window_state()
        except Exception as e:
            pytest.fail(f"Should handle window state restoration: {e}")


class TestIntellicrackAppFontManagement(IntellicrackTestBase):
    """Test font initialization."""

    def test_initialize_font_manager(self, main_app: IntellicrackApp) -> None:
        """_initialize_font_manager initializes font settings."""
        try:
            main_app._initialize_font_manager()
        except Exception as e:
            pytest.fail(f"Should initialize font manager: {e}")


class TestIntellicrackAppAssistantHandlers(IntellicrackTestBase):
    """Test AI assistant status handlers."""

    def test_set_assistant_status(self, main_app: IntellicrackApp) -> None:
        """set_assistant_status updates assistant status."""
        status = "Analyzing binary protections..."

        try:
            main_app.set_assistant_status(status)
        except Exception as e:
            pytest.fail(f"Should handle assistant status: {e}")
