"""User interface components for Intellicrack.

This package provides PyQt6-based UI components including the main
application window, chat panel, tool output display, and configuration
dialogs.
"""

from __future__ import annotations

from .app import AsyncWorker, MainWindow
from .chat import ChatInput, ChatPanel, MessageBubble
from .highlighter import (
    AssemblySyntaxHighlighter,
    CSyntaxHighlighter,
    HighlightRule,
    JavaScriptSyntaxHighlighter,
    PythonSyntaxHighlighter,
    get_highlighter_for_language,
)
from .provider_config import (
    ModelSelectionDialog,
    ProviderConfigDialog,
    ProviderSettingsWidget,
)
from .sandbox_config import (
    SandboxConfigDialog,
    SandboxMonitorWidget,
)
from .session_manager import (
    NewSessionDialog,
    SessionManagerDialog,
)
from .tool_config import (
    ToolConfigDialog,
    ToolSettingsWidget,
    ToolStatusDialog,
)
from .tools import (
    CodeDisplay,
    FunctionListPanel,
    ToolOutputPanel,
    ToolTab,
    XRefPanel,
)


__all__: list[str] = [
    "AssemblySyntaxHighlighter",
    "AsyncWorker",
    "CSyntaxHighlighter",
    "ChatInput",
    "ChatPanel",
    "CodeDisplay",
    "FunctionListPanel",
    "HighlightRule",
    "JavaScriptSyntaxHighlighter",
    "MainWindow",
    "MessageBubble",
    "ModelSelectionDialog",
    "NewSessionDialog",
    "ProviderConfigDialog",
    "ProviderSettingsWidget",
    "PythonSyntaxHighlighter",
    "SandboxConfigDialog",
    "SandboxMonitorWidget",
    "SessionManagerDialog",
    "ToolConfigDialog",
    "ToolOutputPanel",
    "ToolSettingsWidget",
    "ToolStatusDialog",
    "ToolTab",
    "XRefPanel",
    "get_highlighter_for_language",
]
