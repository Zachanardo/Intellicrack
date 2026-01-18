"""Main application window for Intellicrack.

This module provides the main PyQt6 application window that combines
all UI components and connects them to the orchestrator.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QCloseEvent


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from ..core.config import Config
    from ..core.orchestrator import Orchestrator
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QToolBar,
    QWidget,
)

from ..core.logging import get_logger
from ..core.types import Message, ProviderName, ToolCall, ToolResult
from ..sandbox import SandboxManager
from .chat import ChatPanel
from .provider_config import ModelRefreshWorker, ProviderConfigDialog
from .resources import FontManager, IconManager, ThemeManager
from .sandbox_config import SandboxConfigDialog
from .session_manager import SessionManagerDialog
from .tool_config import ToolConfigDialog, ToolStatusDialog
from .tools import ToolOutputPanel


_logger = get_logger("ui.app")

_MAX_RESULT_DISPLAY_LEN = 500


class AsyncWorker(QThread):
    """Worker thread for running async operations.

    Runs an asyncio event loop in a separate thread to execute
    async operations without blocking the UI.
    """

    finished = pyqtSignal(object)
    error = pyqtSignal(Exception)

    def __init__(
        self,
        coro: Coroutine[Any, Any, Any],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the async worker.

        Args:
            coro: Coroutine to execute.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._coro: Coroutine[Any, Any, Any] = coro

    def run(self) -> None:
        """Run the coroutine in a new event loop."""
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result: object = loop.run_until_complete(self._coro)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(e)
        finally:
            if loop is not None:
                loop.close()


class MainWindow(QMainWindow):
    """Main application window for Intellicrack.

    Combines chat panel, tool output panel, menus, and toolbar
    into the main application interface.
    """

    message_received = pyqtSignal(Message)
    tool_call_received = pyqtSignal(ToolCall)
    tool_result_received = pyqtSignal(ToolResult)
    stream_chunk_received = pyqtSignal(str)
    status_update = pyqtSignal(str)

    def __init__(
        self,
        config: Config,
        orchestrator: Orchestrator,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the main window.

        Args:
            config: Application configuration.
            orchestrator: AI agent orchestrator.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._orchestrator = orchestrator
        self._current_worker: AsyncWorker | None = None
        self._stream_append: Callable[[str], None] | None = None
        self._sandbox_manager = SandboxManager()
        self._model_refresh_worker: ModelRefreshWorker | None = None

        self._icon_manager = IconManager.get_instance()
        self._font_manager = FontManager.get_instance()
        self._theme_manager = ThemeManager.get_instance()

        self._font_manager.load_fonts()

        self._setup_ui()
        self._setup_menus()
        self._setup_toolbar()
        self._setup_statusbar()
        self._connect_signals()
        self._configure_orchestrator()

        self.setWindowTitle("Intellicrack")
        self.setWindowIcon(self._icon_manager.get_app_icon())
        self.resize(1400, 900)

    def _setup_ui(self) -> None:
        """Set up the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Horizontal)

        self._chat_panel = ChatPanel()
        self._chat_panel.setMinimumWidth(400)
        self._splitter.addWidget(self._chat_panel)

        self._tool_panel = ToolOutputPanel()
        self._tool_panel.setMinimumWidth(500)
        self._splitter.addWidget(self._tool_panel)

        self._splitter.setSizes([500, 900])

        layout.addWidget(self._splitter)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QMenuBar {
                background-color: #2d2d30;
                color: #d4d4d4;
                border-bottom: 1px solid #3e3e42;
            }
            QMenuBar::item:selected {
                background-color: #3e3e42;
            }
            QMenu {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            QToolBar {
                background-color: #2d2d30;
                border: none;
                border-bottom: 1px solid #3e3e42;
                spacing: 4px;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
        """)

    def _setup_menus(self) -> None:  # noqa: PLR0914
        """Set up the menu bar."""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")

        load_action = QAction("Load Binary...", self)
        load_action.setShortcut("Ctrl+O")
        load_action.triggered.connect(self._on_load_binary)
        file_menu.addAction(load_action)

        file_menu.addSeparator()

        new_session_action = QAction("New Session", self)
        new_session_action.setShortcut("Ctrl+N")
        new_session_action.triggered.connect(self._on_new_session)
        file_menu.addAction(new_session_action)

        load_session_action = QAction("Load Session...", self)
        load_session_action.triggered.connect(self._on_load_session)
        file_menu.addAction(load_session_action)

        save_session_action = QAction("Save Session", self)
        save_session_action.setShortcut("Ctrl+S")
        save_session_action.triggered.connect(self._on_save_session)
        file_menu.addAction(save_session_action)

        file_menu.addSeparator()

        export_action = QAction("Export Chat...", self)
        export_action.triggered.connect(self._on_export_chat)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        tools_menu = menubar.addMenu("&Tools")

        tool_status_action = QAction("Tool Status...", self)
        tool_status_action.triggered.connect(self._on_tool_status)
        tools_menu.addAction(tool_status_action)

        configure_tools_action = QAction("Configure Tools...", self)
        configure_tools_action.triggered.connect(self._on_configure_tools)
        tools_menu.addAction(configure_tools_action)

        providers_menu = menubar.addMenu("&Providers")

        configure_providers_action = QAction("Configure Providers...", self)
        configure_providers_action.triggered.connect(self._on_configure_providers)
        providers_menu.addAction(configure_providers_action)

        refresh_models_action = QAction("Refresh Models", self)
        refresh_models_action.triggered.connect(self._on_refresh_models)
        providers_menu.addAction(refresh_models_action)

        sandbox_menu = menubar.addMenu("&Sandbox")

        configure_sandbox_action = QAction("Configure Sandbox...", self)
        configure_sandbox_action.triggered.connect(self._on_configure_sandbox)
        sandbox_menu.addAction(configure_sandbox_action)

        open_sandbox_action = QAction("Open Sandbox", self)
        open_sandbox_action.triggered.connect(self._on_open_sandbox)
        sandbox_menu.addAction(open_sandbox_action)

        settings_menu = menubar.addMenu("&Settings")

        preferences_action = QAction("Preferences...", self)
        preferences_action.triggered.connect(self._on_preferences)
        settings_menu.addAction(preferences_action)

        help_menu = menubar.addMenu("&Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self) -> None:
        """Set up the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setFixedHeight(40)
        self.addToolBar(toolbar)

        load_btn = QPushButton("Load Binary")
        load_btn.setObjectName("secondary_button")
        load_btn.clicked.connect(self._on_load_binary)
        toolbar.addWidget(load_btn)

        toolbar.addSeparator()

        provider_label = QLabel("Provider:")
        provider_label.setObjectName("toolbar_label")
        toolbar.addWidget(provider_label)

        self._provider_combo = QComboBox()
        self._provider_combo.setMinimumWidth(120)
        self._provider_combo.setObjectName("toolbar_combo")
        for provider in ProviderName:
            self._provider_combo.addItem(provider.value.title(), provider)
        self._provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        toolbar.addWidget(self._provider_combo)

        model_label = QLabel("Model:")
        model_label.setObjectName("toolbar_label")
        toolbar.addWidget(model_label)

        self._model_combo = QComboBox()
        self._model_combo.setMinimumWidth(200)
        self._model_combo.setObjectName("toolbar_combo")
        toolbar.addWidget(self._model_combo)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        self._sandbox_btn = QPushButton("Sandbox: OFF")
        self._sandbox_btn.setCheckable(True)
        self._sandbox_btn.setObjectName("toggle_button")
        self._sandbox_btn.toggled.connect(self._on_sandbox_toggled)
        toolbar.addWidget(self._sandbox_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("danger_button")
        cancel_btn.clicked.connect(self._on_cancel)
        toolbar.addWidget(cancel_btn)

    def _setup_statusbar(self) -> None:
        """Set up the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        self._status_label = QLabel("Ready")
        self._statusbar.addWidget(self._status_label)

        self._binary_label = QLabel()
        self._statusbar.addPermanentWidget(self._binary_label)

        self._token_label = QLabel()
        self._statusbar.addPermanentWidget(self._token_label)

    def _connect_signals(self) -> None:
        """Connect Qt signals."""
        self._chat_panel.message_submitted.connect(self._on_user_message)
        self.message_received.connect(self._chat_panel.add_message)
        self.tool_call_received.connect(self._on_tool_call)
        self.tool_result_received.connect(self._on_tool_result)
        self.stream_chunk_received.connect(self._on_stream_chunk)
        self.status_update.connect(self._update_status)

    def _configure_orchestrator(self) -> None:
        """Configure orchestrator callbacks."""
        self._orchestrator.set_message_callback(self.message_received.emit)
        self._orchestrator.set_tool_call_callback(self.tool_call_received.emit)
        self._orchestrator.set_tool_result_callback(self.tool_result_received.emit)
        self._orchestrator.set_stream_callback(self.stream_chunk_received.emit)

    def _on_user_message(self, text: str) -> None:
        """Handle user message submission.

        Args:
            text: User's message text.
        """
        self._chat_panel.set_input_enabled(False)
        self._stream_append = self._chat_panel.add_streaming_message()
        self.status_update.emit("Processing...")

        async def process() -> None:
            await self._orchestrator.process_user_input(text)

        self._run_async(process())

    def _on_stream_chunk(self, chunk: str) -> None:
        """Handle streaming response chunk.

        Args:
            chunk: Text chunk from LLM.
        """
        if self._stream_append:
            self._stream_append(chunk)

    def _on_tool_call(self, call: ToolCall) -> None:
        """Handle tool call notification.

        Args:
            call: The tool call being executed.
        """
        self.status_update.emit(f"Running: {call.tool_name}.{call.function_name}")
        self._tool_panel.log(
            f"[CALL] {call.tool_name}.{call.function_name}"
        )

    def _on_tool_result(self, result: ToolResult) -> None:
        """Handle tool result notification.

        Args:
            result: The tool execution result.
        """
        status = "SUCCESS" if result.success else "FAILED"
        self._tool_panel.log(
            f"[{status}] Duration: {result.duration_ms:.1f}ms"
        )

        if result.success and result.result:
            result_str = str(result.result)
            if len(result_str) > _MAX_RESULT_DISPLAY_LEN:
                result_str = result_str[:_MAX_RESULT_DISPLAY_LEN - 3] + "..."
            self._tool_panel.log(f"Result: {result_str}")

        if result.error:
            self._tool_panel.log(f"Error: {result.error}")

    def _run_async(self, coro: Coroutine[Any, Any, Any]) -> None:
        """Run an async operation in a worker thread.

        Args:
            coro: Coroutine to execute.
        """
        self._current_worker = AsyncWorker(coro, self)
        self._current_worker.finished.connect(self._on_async_finished)
        self._current_worker.error.connect(self._on_async_error)
        self._current_worker.start()

    def _on_async_finished(self, result: object) -> None:  # noqa: ARG002
        """Handle async operation completion.

        Args:
            result: Operation result.
        """
        self._chat_panel.set_input_enabled(True)
        self._stream_append = None
        self.status_update.emit("Ready")

    def _on_async_error(self, error: Exception) -> None:
        """Handle async operation error.

        Args:
            error: The error that occurred.
        """
        self._chat_panel.set_input_enabled(True)
        self._stream_append = None
        self.status_update.emit("Error")
        QMessageBox.critical(self, "Error", str(error))

    def _update_status(self, status: str) -> None:
        """Update the status bar.

        Args:
            status: Status message.
        """
        self._status_label.setText(status)

    def _on_load_binary(self) -> None:
        """Handle load binary action."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "Executables (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if path:
            self._load_binary(Path(path))

    def _load_binary(self, path: Path) -> None:
        """Load a binary file.

        Args:
            path: Path to the binary.
        """
        async def load() -> None:
            await self._orchestrator.add_binary(path)

        self.status_update.emit(f"Loading {path.name}...")
        self._run_async(load())

    def _on_new_session(self) -> None:
        """Handle new session action."""
        provider = self._provider_combo.currentData()
        model = self._model_combo.currentText()

        if not model:
            QMessageBox.warning(self, "Warning", "Please select a model first.")
            return

        async def create_session() -> None:
            await self._orchestrator.start_session(provider, model)

        self._chat_panel.clear_messages()
        self._tool_panel.clear_all()
        self.status_update.emit("Creating new session...")
        self._run_async(create_session())

    def _on_load_session(self) -> None:
        """Handle load session action."""
        dialog = SessionManagerDialog(parent=self)
        if dialog.exec():
            session_id = dialog.get_selected_session_id()
            if session_id:
                async def load_session() -> None:
                    await self._orchestrator.load_session(session_id)

                self._chat_panel.clear_messages()
                self._tool_panel.clear_all()
                self.status_update.emit(f"Loading session {session_id}...")
                self._run_async(load_session())

    def _on_save_session(self) -> None:
        """Handle save session action."""
        async def save_session() -> None:
            await self._orchestrator.save_session()

        self.status_update.emit("Saving session...")
        self._run_async(save_session())

    def _on_export_chat(self) -> None:
        """Handle export chat action."""
        messages = self._chat_panel.get_messages()
        if not messages:
            QMessageBox.information(self, "Export", "No messages to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Chat",
            "",
            "Text Files (*.txt);;Markdown (*.md);;All Files (*)",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for msg in messages:
                    role = msg.role.upper()
                    f.write(f"[{role}] {msg.timestamp.strftime('%H:%M:%S')}\n")
                    f.write(f"{msg.content}\n\n")
            QMessageBox.information(self, "Export", f"Chat exported to {path}")

    def _on_tool_status(self) -> None:
        """Handle tool status action."""
        dialog = ToolStatusDialog(parent=self)
        dialog.exec()

    def _on_configure_tools(self) -> None:
        """Handle configure tools action."""
        dialog = ToolConfigDialog(
            tools_directory=self._config.tools_directory,
            parent=self,
        )
        if dialog.exec():
            settings = dialog.get_settings()
            self._apply_tool_settings(settings)

    def _apply_tool_settings(self, settings: dict[str, dict[str, Any]]) -> None:
        """Apply tool configuration settings.

        The ToolConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Tool settings dictionary mapping tool IDs to their settings.
        """
        del settings
        self.status_update.emit("Tool settings saved")

    def _on_configure_providers(self) -> None:
        """Handle configure providers action."""
        dialog = ProviderConfigDialog(parent=self)
        if dialog.exec():
            settings = dialog.get_settings()
            self._apply_provider_settings(settings)

    def _apply_provider_settings(self, settings: dict[str, dict[str, Any]]) -> None:
        """Apply provider configuration settings.

        The ProviderConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Provider settings dictionary mapping provider IDs to their settings.
        """
        del settings
        self.status_update.emit("Provider settings saved")

    def _on_refresh_models(self) -> None:
        """Handle refresh models action."""
        provider = self._provider_combo.currentData()
        if not provider:
            QMessageBox.warning(self, "Warning", "Please select a provider first.")
            return

        provider_id = provider.value if hasattr(provider, "value") else str(provider)

        env_vars: dict[str, str] = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        api_key = ""
        if provider_id in env_vars:
            api_key = os.environ.get(env_vars[provider_id], "")

        config_path = Path.home() / ".intellicrack" / "providers.json"
        if config_path.exists():
            try:
                with open(config_path, encoding="utf-8") as f:
                    provider_settings: dict[str, Any] = json.load(f)
                    provider_data: dict[str, Any] = provider_settings.get(provider_id, {})
                    if isinstance(provider_data, dict):
                        config_key: str = str(provider_data.get("api_key", ""))
                        if config_key:
                            api_key = config_key
            except (json.JSONDecodeError, OSError):
                pass

        self.status_update.emit("Refreshing models...")
        self._model_combo.clear()
        self._model_combo.setEnabled(False)

        self._model_refresh_worker = ModelRefreshWorker(provider_id, api_key, None, self)
        self._model_refresh_worker.finished.connect(self._on_models_refresh_finished)
        self._model_refresh_worker.start()

    def _on_models_refresh_finished(
        self, success: bool, models: list[str], message: str
    ) -> None:
        """Handle models refresh completion.

        Args:
            success: Whether the refresh was successful.
            models: List of available model names.
            message: Status message.
        """
        self._model_combo.setEnabled(True)
        if success and models:
            self._model_combo.clear()
            self._model_combo.addItems(models)
            self.status_update.emit(f"Found {len(models)} models")
        else:
            self.status_update.emit("Failed to refresh models")
            QMessageBox.warning(self, "Model Refresh Failed", message)

    def _on_configure_sandbox(self) -> None:
        """Handle configure sandbox action."""
        dialog = SandboxConfigDialog(
            sandbox_manager=self._sandbox_manager,
            parent=self,
        )
        if dialog.exec():
            settings = dialog.get_settings()
            self._apply_sandbox_settings(settings)

    def _apply_sandbox_settings(self, settings: dict[str, Any]) -> None:
        """Apply sandbox configuration settings.

        The SandboxConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Sandbox settings dictionary.
        """
        del settings
        self.status_update.emit("Sandbox settings saved")

    def _on_open_sandbox(self) -> None:
        """Handle open sandbox action."""
        async def open_sandbox() -> object:
            available_types = await self._sandbox_manager.get_available_types()
            if not available_types:
                return None

            sandbox_type = available_types[0]
            return await self._sandbox_manager.create(
                sandbox_type=sandbox_type,
                auto_start=True,
            )

        def on_sandbox_opened(result: object) -> None:
            if result is None:
                QMessageBox.warning(
                    self,
                    "Sandbox Unavailable",
                    "No sandbox environment is available.\n\n"
                    "Windows Sandbox requires Windows 10/11 Pro or Enterprise.\n"
                    "QEMU requires QEMU to be installed.",
                )
                self.status_update.emit("No sandbox available")
            else:
                self._sandbox_btn.setChecked(True)
                self.status_update.emit("Sandbox opened")

        self.status_update.emit("Opening sandbox...")
        worker = AsyncWorker(open_sandbox(), self)
        worker.finished.connect(on_sandbox_opened)
        worker.error.connect(lambda e: QMessageBox.critical(self, "Error", str(e)))
        worker.start()
        self._current_worker = worker

    def _on_preferences(self) -> None:
        """Handle preferences action."""
        from .preferences import PreferencesDialog  # noqa: PLC0415

        dialog = PreferencesDialog(self._config, self)
        if dialog.exec():
            self._config = dialog.get_config()
            self.status_update.emit("Preferences saved")

    def _on_about(self) -> None:
        """Handle about action."""
        QMessageBox.about(
            self,
            "About Intellicrack",
            "Intellicrack\n\n"
            "AI-powered reverse engineering platform for analyzing\n"
            "software licensing protections.\n\n"
            "Version 2.0.0",
        )

    def _on_provider_changed(self, index: int) -> None:
        """Handle provider selection change.

        Args:
            index: New selection index.
        """
        del index
        provider = self._provider_combo.currentData()
        _logger.info("Provider changed to %s", provider.value if provider else "None")

    def _on_sandbox_toggled(self, checked: bool) -> None:
        """Handle sandbox toggle.

        Args:
            checked: Whether sandbox is enabled.
        """
        self._sandbox_btn.setText(f"Sandbox: {'ON' if checked else 'OFF'}")

    def _on_cancel(self) -> None:
        """Handle cancel button click."""
        async def cancel() -> None:
            await self._orchestrator.cancel()

        self._run_async(cancel())
        self.status_update.emit("Cancelling...")

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Handle window close event.

        Args:
            event: Close event.
        """
        async def shutdown() -> None:
            await self._orchestrator.shutdown()

        if self._current_worker and self._current_worker.isRunning():
            self._current_worker.wait()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(shutdown())
        loop.close()

        event.accept()
