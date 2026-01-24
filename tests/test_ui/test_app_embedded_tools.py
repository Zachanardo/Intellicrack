"""Tests for embedded tools UI integration in MainWindow.

Tests the menu actions, toolbar buttons, and handlers for x64dbg,
Cutter, and HxD embedded tool integration.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide QApplication for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def mock_orchestrator() -> MagicMock:
    """Create a mock orchestrator for MainWindow."""
    orchestrator = MagicMock()
    orchestrator.set_message_callback = MagicMock()
    orchestrator.set_tool_call_callback = MagicMock()
    orchestrator.set_tool_result_callback = MagicMock()
    orchestrator.set_stream_callback = MagicMock()
    orchestrator.set_async_confirmation_callback = MagicMock()
    orchestrator._config = MagicMock()
    orchestrator.shutdown = AsyncMock()
    return orchestrator


@pytest.fixture
def mock_config() -> MagicMock:
    """Create a mock config for MainWindow."""
    config = MagicMock()
    config.tools_directory = Path("tools")
    return config


class TestEmbeddedToolsMenuIntegration:
    """Tests for embedded tools menu items in MainWindow."""

    def test_embedded_tools_menu_exists(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify Embedded Tools submenu is created in Tools menu."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                menubar = window.menuBar()
                tools_menu = None
                for action in menubar.actions():
                    if action.text() == "&Tools":
                        tools_menu = action.menu()
                        break

                assert tools_menu is not None, "Tools menu not found"

                embedded_menu = None
                for action in tools_menu.actions():
                    if action.text() == "&Embedded Tools":
                        embedded_menu = action.menu()
                        break

                assert embedded_menu is not None, "Embedded Tools submenu not found"
            finally:
                window.close()

    def test_embedded_tools_menu_actions_count(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify all 6 menu actions exist in Embedded Tools submenu."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                menubar = window.menuBar()
                tools_menu = None
                for action in menubar.actions():
                    if action.text() == "&Tools":
                        tools_menu = action.menu()
                        break

                embedded_menu = None
                if tools_menu:
                    for action in tools_menu.actions():
                        if action.text() == "&Embedded Tools":
                            embedded_menu = action.menu()
                            break

                assert embedded_menu is not None

                action_texts = [a.text() for a in embedded_menu.actions() if not a.isSeparator()]
                expected_actions = [
                    "Open x64dbg Debugger",
                    "Open Cutter Analysis",
                    "Open HxD Hex Editor",
                    "Debug Current Binary...",
                    "Analyze Current Binary...",
                    "Hex Edit Current Binary...",
                ]

                for expected in expected_actions:
                    assert expected in action_texts, f"Missing action: {expected}"
            finally:
                window.close()


class TestToolbarButtonsIntegration:
    """Tests for embedded tools toolbar buttons."""

    def test_toolbar_has_tool_buttons(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify x64dbg, Cutter, and HxD buttons exist in toolbar."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                assert hasattr(window, "_x64dbg_btn"), "x64dbg button not found"
                assert hasattr(window, "_cutter_btn"), "Cutter button not found"
                assert hasattr(window, "_hxd_btn"), "HxD button not found"

                assert window._x64dbg_btn.text() == "x64dbg"
                assert window._cutter_btn.text() == "Cutter"
                assert window._hxd_btn.text() == "HxD"
            finally:
                window.close()

    def test_toolbar_button_tooltips(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify toolbar buttons have correct tooltips."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                assert "x64dbg" in window._x64dbg_btn.toolTip()
                assert "Cutter" in window._cutter_btn.toolTip()
                assert "HxD" in window._hxd_btn.toolTip()
            finally:
                window.close()


class TestEmbeddedToolHandlers:
    """Tests for embedded tool handler methods."""

    def test_on_open_x64dbg_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_x64dbg calls add_x64dbg_tab."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                window._tool_panel.add_x64dbg_tab = MagicMock(return_value=mock_widget)

                window._on_open_x64dbg()

                window._tool_panel.add_x64dbg_tab.assert_called_once_with(is_64bit=True)
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()

    def test_on_open_x64dbg_handles_none_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_x64dbg shows error when widget creation fails."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                window._tool_panel.add_x64dbg_tab = MagicMock(return_value=None)

                with patch.object(window, "_show_tool_error") as mock_error:
                    window._on_open_x64dbg()
                    mock_error.assert_called_once()
                    assert "x64dbg" in mock_error.call_args[0][0]
            finally:
                window.close()

    def test_on_open_cutter_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_cutter calls add_cutter_tab."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                window._tool_panel.add_cutter_tab = MagicMock(return_value=mock_widget)

                window._on_open_cutter()

                window._tool_panel.add_cutter_tab.assert_called_once()
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()

    def test_on_open_hxd_creates_widget(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _on_open_hxd calls add_hxd_tab."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                mock_widget = MagicMock()
                mock_widget.start_tool.return_value = True
                window._tool_panel.add_hxd_tab = MagicMock(return_value=mock_widget)

                window._on_open_hxd()

                window._tool_panel.add_hxd_tab.assert_called_once()
                mock_widget.start_tool.assert_called_once()
            finally:
                window.close()


class TestCurrentBinaryHandlers:
    """Tests for current binary operation handlers."""

    def test_debug_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for debug."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    window._on_debug_current_binary()
                    mock_warn.assert_called_once_with("debug")
            finally:
                window.close()

    def test_analyze_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for analysis."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    window._on_analyze_current_binary()
                    mock_warn.assert_called_once_with("analyze")
            finally:
                window.close()

    def test_hex_edit_current_binary_without_binary_shows_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify warning shown when no binary is loaded for hex edit."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                window._current_binary = None

                with patch.object(window, "_show_no_binary_warning") as mock_warn:
                    window._on_hex_edit_current_binary()
                    mock_warn.assert_called_once_with("hex edit")
            finally:
                window.close()

    def test_debug_current_binary_with_binary_calls_open_in_x64dbg(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to x64dbg when loaded."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                window._tool_panel.open_in_x64dbg = MagicMock(return_value=True)

                window._on_debug_current_binary()

                window._tool_panel.open_in_x64dbg.assert_called_once_with(test_path)
            finally:
                window.close()

    def test_analyze_current_binary_with_binary_calls_open_in_cutter(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to Cutter when loaded."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                window._tool_panel.open_in_cutter = MagicMock(return_value=True)

                window._on_analyze_current_binary()

                window._tool_panel.open_in_cutter.assert_called_once_with(test_path)
            finally:
                window.close()

    def test_hex_edit_current_binary_with_binary_calls_open_in_hxd(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify binary is passed to HxD when loaded."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/binary.exe")
                window._current_binary = test_path
                window._tool_panel.open_in_hxd = MagicMock(return_value=True)

                window._on_hex_edit_current_binary()

                window._tool_panel.open_in_hxd.assert_called_once_with(test_path)
            finally:
                window.close()


class TestCurrentBinaryTracking:
    """Tests for current binary tracking in MainWindow."""

    def test_current_binary_initialized_to_none(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _current_binary starts as None."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                assert window._current_binary is None
            finally:
                window.close()

    def test_load_binary_sets_current_binary(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _load_binary updates _current_binary."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                test_path = Path("/test/sample.exe")

                with patch.object(window, "_run_async"):
                    window._load_binary(test_path)

                assert window._current_binary == test_path
            finally:
                window.close()


class TestErrorDialogs:
    """Tests for error and warning dialog display."""

    def test_show_tool_error_displays_warning(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _show_tool_error displays QMessageBox warning."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                with patch.object(QMessageBox, "warning") as mock_warning:
                    window._show_tool_error("TestTool", "Test error message")

                    mock_warning.assert_called_once()
                    call_args = mock_warning.call_args
                    assert "TestTool" in call_args[0][1]
                    assert "Test error message" in call_args[0][2]
            finally:
                window.close()

    def test_show_no_binary_warning_displays_info(
        self,
        qapp: QApplication,
        mock_config: MagicMock,
        mock_orchestrator: MagicMock,
    ) -> None:
        """Verify _show_no_binary_warning displays QMessageBox information."""
        with patch("intellicrack.ui.app.SandboxManager"):
            from intellicrack.ui.app import MainWindow

            window = MainWindow(mock_config, mock_orchestrator)
            try:
                with patch.object(QMessageBox, "information") as mock_info:
                    window._show_no_binary_warning("test action")

                    mock_info.assert_called_once()
                    call_args = mock_info.call_args
                    assert "test action" in call_args[0][2]
            finally:
                window.close()
