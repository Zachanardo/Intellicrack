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

logger = logging.getLogger(__name__)

# Core components
try:
    from .ai_bridge import AIBinaryBridge, BinaryContextBuilder
except ImportError as e:
    logger.warning("Failed to import ai_bridge: %s", e)
    AIBinaryBridge = None
    BinaryContextBuilder = None

# API functions
try:
    from .api import (  # Analysis operations; Utility operations; UI operations; Integration operations; File operations
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
    # Set all API functions to None
    add_hex_viewer_to_application = analyze_binary_data = bytes_to_hex_string = create_binary_context = None
    create_hex_viewer_dialog = create_hex_viewer_widget = hex_string_to_bytes = integrate_with_intellicrack = None
    launch_hex_viewer = open_hex_file = read_hex_region = register_ai_tools = search_binary_pattern = None
    suggest_binary_edits = write_hex_region = None

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

# Integration functions
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
    initialize_hex_viewer = integrate_enhanced_hex_viewer = register_hex_viewer_ai_tools = None
    restore_standard_hex_viewer = show_enhanced_hex_viewer = None

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


# Large file optimization components
try:
    from .large_file_handler import LargeFileHandler as LargeFileHandler
    from .large_file_handler import MemoryConfig as MemoryConfig
    from .large_file_handler import MemoryStrategy as MemoryStrategy
    from .performance_monitor import PerformanceMonitor as PerformanceMonitor
    from .performance_monitor import PerformanceWidget as PerformanceWidget

    LARGE_FILE_SUPPORT = True
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    LARGE_FILE_SUPPORT = False


# Public API - explicitly export all imported components
__all__ = [
    # Core components
    "AIBinaryBridge",
    "BinaryContextBuilder",
    "ChunkManager",
    "VirtualFileAccess",
    "HexViewerDialog",
    "HexHighlighter",
    "HighlightType",
    "HexViewRenderer",
    "ViewMode",
    "parse_hex_view",
    "HexViewerWidget",
    # API functions
    "add_hex_viewer_to_application",
    "analyze_binary_data",
    "bytes_to_hex_string",
    "create_binary_context",
    "create_hex_viewer_dialog",
    "create_hex_viewer_widget",
    "hex_string_to_bytes",
    "integrate_with_intellicrack",
    "launch_hex_viewer",
    "open_hex_file",
    "read_hex_region",
    "register_ai_tools",
    "search_binary_pattern",
    "suggest_binary_edits",
    "write_hex_region",
    # Integration functions
    "initialize_hex_viewer",
    "integrate_enhanced_hex_viewer",
    "register_hex_viewer_ai_tools",
    "restore_standard_hex_viewer",
    "show_enhanced_hex_viewer",
    # Convenience aliases
    "show_hex_viewer",
    "integrate",
    "HexViewer",
    # Large file optimization (conditionally available)
    "LARGE_FILE_SUPPORT",
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

# Convenience aliases
show_hex_viewer = show_enhanced_hex_viewer if show_enhanced_hex_viewer else None
integrate = integrate_with_intellicrack if integrate_with_intellicrack else None

# Main hex viewer class (alias for compatibility)
HexViewer = HexViewerWidget if HexViewerWidget else None
