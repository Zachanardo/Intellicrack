"""Type definitions for Intellicrack.

This module provides Pydantic models and Protocol definitions for type-safe
data structures used throughout the Intellicrack codebase.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from intellicrack.types.analysis import (
    AIAutoGenerationCandidate,
    AIIntegrationResult,
    AIScriptSuggestion,
    AutonomousGenerationInfo,
    BasicFileInfo,
    BinaryAnalysisResult,
    ELFAnalysisResult,
    ExploitPayloadResult,
    ExploitStrategyResult,
    ExportInfo,
    FridaScriptSuggestion,
    GhidraScriptSuggestion,
    ImportInfo,
    MachOAnalysisResult,
    MachOHeaderInfo,
    MachOSegmentInfo,
    OptimizedAnalysisResult,
    PEAnalysisResult,
    PerformanceMetrics,
    SectionInfo,
    SymbolInfo,
)
from intellicrack.types.ui import (
    BinarySelectionWidgets,
    DialogResult,
    FileDialogResult,
    HeadlessFileDialog,
    HeadlessMessageBox,
    HeadlessWidget,
    MessageBoxProtocol,
    QtFileDialogAdapter,
    QtMessageBoxAdapter,
    StandardButton,
    WidgetProtocol,
    get_file_dialog,
    get_message_box,
)


__all__ = [
    "AIAutoGenerationCandidate",
    "AIIntegrationResult",
    "AIScriptSuggestion",
    "AutonomousGenerationInfo",
    "BasicFileInfo",
    "BinaryAnalysisResult",
    "BinarySelectionWidgets",
    "DialogResult",
    "ELFAnalysisResult",
    "ExportInfo",
    "ExploitPayloadResult",
    "ExploitStrategyResult",
    "FileDialogResult",
    "FridaScriptSuggestion",
    "GhidraScriptSuggestion",
    "HeadlessFileDialog",
    "HeadlessMessageBox",
    "HeadlessWidget",
    "ImportInfo",
    "MachOAnalysisResult",
    "MachOHeaderInfo",
    "MachOSegmentInfo",
    "MessageBoxProtocol",
    "OptimizedAnalysisResult",
    "PEAnalysisResult",
    "PerformanceMetrics",
    "QtFileDialogAdapter",
    "QtMessageBoxAdapter",
    "SectionInfo",
    "StandardButton",
    "SymbolInfo",
    "WidgetProtocol",
    "get_file_dialog",
    "get_message_box",
]
