"""Hexview package for Intellicrack.

This package provides advanced hexadecimal viewing and editing capabilities
including search functionality, data visualization, and binary analysis tools.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from typing import Any


logger = logging.getLogger(__name__)

AIBinaryBridge: Any
BinaryContextBuilder: Any
ChunkManager: Any
VirtualFileAccess: Any
HexViewerDialog: Any
HexHighlighter: Any
HighlightType: Any
HexViewRenderer: Any
ViewMode: Any
parse_hex_view: Any
HexViewerWidget: Any
initialize_hex_viewer: Any
integrate_enhanced_hex_viewer: Any
register_hex_viewer_ai_tools: Any
restore_standard_hex_viewer: Any
show_enhanced_hex_viewer: Any
add_hex_viewer_to_application: Any
analyze_binary_data: Any
bytes_to_hex_string: Any
create_binary_context: Any
create_hex_viewer_dialog: Any
create_hex_viewer_widget: Any
hex_string_to_bytes: Any
integrate_with_intellicrack: Any
launch_hex_viewer: Any
open_hex_file: Any
read_hex_region: Any
register_ai_tools: Any
search_binary_pattern: Any
suggest_binary_edits: Any
write_hex_region: Any

try:
    from .ai_bridge import AIBinaryBridge, BinaryContextBuilder
except ImportError as e:
    logger.warning("Failed to import ai_bridge: %s", e)
    AIBinaryBridge = None
    BinaryContextBuilder = None

try:
    from .api import (
        add_hex_viewer_to_application,
        analyze_binary_data,
        bytes_to_hex_string,
        create_binary_context,
        create_hex_viewer_dialog,
        create_hex_viewer_widget,
        hex_string_to_bytes,
        integrate_with_intellicrack,
        launch_hex_viewer,
        open_hex_file,
        read_hex_region,
        register_ai_tools,
        search_binary_pattern,
        suggest_binary_edits,
        write_hex_region,
    )
except ImportError as e:
    logger.warning("Failed to import api: %s", e)
    add_hex_viewer_to_application = None
    analyze_binary_data = None
    bytes_to_hex_string = None
    create_binary_context = None
    create_hex_viewer_dialog = None
    create_hex_viewer_widget = None
    hex_string_to_bytes = None
    integrate_with_intellicrack = None
    launch_hex_viewer = None
    open_hex_file = None
    read_hex_region = None
    register_ai_tools = None
    search_binary_pattern = None
    suggest_binary_edits = None
    write_hex_region = None

try:
    from .file_handler import ChunkManager, VirtualFileAccess
except ImportError as e:
    logger.warning("Failed to import file_handler: %s", e)
    ChunkManager = None
    VirtualFileAccess = None

try:
    from .hex_dialog import HexViewerDialog
except ImportError as e:
    logger.warning("Failed to import hex_dialog: %s", e)
    HexViewerDialog = None

try:
    from .hex_highlighter import HexHighlighter, HighlightType
except ImportError as e:
    logger.warning("Failed to import hex_highlighter: %s", e)
    HexHighlighter = None
    HighlightType = None

try:
    from .hex_renderer import HexViewRenderer, ViewMode, parse_hex_view
except ImportError as e:
    logger.warning("Failed to import hex_renderer: %s", e)
    HexViewRenderer = None
    ViewMode = None
    parse_hex_view = None

try:
    from .hex_widget import HexViewerWidget
except ImportError as e:
    logger.warning("Failed to import hex_widget: %s", e)
    HexViewerWidget = None

try:
    from .integration import (
        initialize_hex_viewer,
        integrate_enhanced_hex_viewer,
        register_hex_viewer_ai_tools,
        restore_standard_hex_viewer,
        show_enhanced_hex_viewer,
    )
except ImportError as e:
    logger.warning("Failed to import integration: %s", e)
    initialize_hex_viewer = None
    integrate_enhanced_hex_viewer = None
    register_hex_viewer_ai_tools = None
    restore_standard_hex_viewer = None
    show_enhanced_hex_viewer = None

"""
Enhanced Hex Viewer/Editor module for Intellicrack.

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

LargeFileHandler: Any
MemoryConfig: Any
MemoryStrategy: Any
PerformanceMonitor: Any
PerformanceWidget: Any

try:
    from .large_file_handler import (
        LargeFileHandler as LargeFileHandler,
        MemoryConfig as MemoryConfig,
        MemoryStrategy as MemoryStrategy,
    )
    from .performance_monitor import (
        PerformanceMonitor as PerformanceMonitor,
        PerformanceWidget as PerformanceWidget,
    )

    LARGE_FILE_SUPPORT: bool = True
except ImportError as e:
    logger.exception("Import error in __init__: %s", e)
    LARGE_FILE_SUPPORT = False
    LargeFileHandler = None
    MemoryConfig = None
    MemoryStrategy = None
    PerformanceMonitor = None
    PerformanceWidget = None


# Public API - explicitly export all imported components
__all__ = [
    "AIBinaryBridge",
    "BinaryContextBuilder",
    "ChunkManager",
    "HexHighlighter",
    "HexViewRenderer",
    "HexViewer",
    "HexViewerDialog",
    "HexViewerWidget",
    "HighlightType",
    "LARGE_FILE_SUPPORT",
    "ViewMode",
    "VirtualFileAccess",
    "add_hex_viewer_to_application",
    "analyze_binary_data",
    "bytes_to_hex_string",
    "create_binary_context",
    "create_hex_viewer_dialog",
    "create_hex_viewer_widget",
    "hex_string_to_bytes",
    "initialize_hex_viewer",
    "integrate",
    "integrate_enhanced_hex_viewer",
    "integrate_with_intellicrack",
    "launch_hex_viewer",
    "open_hex_file",
    "parse_hex_view",
    "read_hex_region",
    "register_ai_tools",
    "register_hex_viewer_ai_tools",
    "restore_standard_hex_viewer",
    "search_binary_pattern",
    "show_enhanced_hex_viewer",
    "show_hex_viewer",
    "suggest_binary_edits",
    "write_hex_region",
]

# Filter out None values from __all__
__all__ = [item for item in __all__ if item not in ["LARGE_FILE_SUPPORT"] and locals().get(item) is not None]

# Conditionally add large file components to __all__ if available
if LARGE_FILE_SUPPORT:
    __all__.extend(
        [
            "LargeFileHandler",
            "MemoryConfig",
            "MemoryStrategy",
            "PerformanceMonitor",
            "PerformanceWidget",
        ],
    )

show_hex_viewer: Any = show_enhanced_hex_viewer if show_enhanced_hex_viewer is not None else None
integrate: Any = integrate_with_intellicrack if integrate_with_intellicrack is not None else None
HexViewer: Any = HexViewerWidget if HexViewerWidget is not None else None
