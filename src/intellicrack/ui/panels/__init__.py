"""UI panels for Intellicrack analysis displays.

This module provides specialized panels for licensing analysis,
stack viewing, and script management within the main application.
"""

from __future__ import annotations

from intellicrack.ui.panels.licensing_panel import LicensingAnalysisPanel
from intellicrack.ui.panels.script_manager import ScriptManagerPanel, ScriptTypeInfo
from intellicrack.ui.panels.stack_viewer import (
    FridaStackSource,
    StackFrame,
    StackViewerPanel,
    X64DbgStackSource,
)


__all__ = [
    "FridaStackSource",
    "LicensingAnalysisPanel",
    "ScriptManagerPanel",
    "ScriptTypeInfo",
    "StackFrame",
    "StackViewerPanel",
    "X64DbgStackSource",
]
