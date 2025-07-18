"""Hexview package for Intellicrack.

This package provides advanced hexadecimal viewing and editing capabilities
including search functionality, data visualization, and binary analysis tools.
"""
from intellicrack.logger import logger

# Core components
from .ai_bridge import AIBinaryBridge, BinaryContextBuilder

# API functions
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
from .file_handler import ChunkManager, VirtualFileAccess
from .hex_dialog import HexViewerDialog
from .hex_highlighter import HexHighlighter, HighlightType
from .hex_renderer import HexViewRenderer, ViewMode, parse_hex_view
from .hex_widget import HexViewerWidget

# Integration functions
from .integration import (
    initialize_hex_viewer,
    integrate_enhanced_hex_viewer,
    register_hex_viewer_ai_tools,
    restore_standard_hex_viewer,
    show_enhanced_hex_viewer,
)

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
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
    'AIBinaryBridge',
    'BinaryContextBuilder',
    'ChunkManager',
    'VirtualFileAccess',
    'HexViewerDialog',
    'HexHighlighter',
    'HighlightType',
    'HexViewRenderer',
    'ViewMode',
    'parse_hex_view',
    'HexViewerWidget',

    # API functions
    'add_hex_viewer_to_application',
    'analyze_binary_data',
    'bytes_to_hex_string',
    'create_binary_context',
    'create_hex_viewer_dialog',
    'create_hex_viewer_widget',
    'hex_string_to_bytes',
    'integrate_with_intellicrack',
    'launch_hex_viewer',
    'open_hex_file',
    'read_hex_region',
    'register_ai_tools',
    'search_binary_pattern',
    'suggest_binary_edits',
    'write_hex_region',

    # Integration functions
    'initialize_hex_viewer',
    'integrate_enhanced_hex_viewer',
    'register_hex_viewer_ai_tools',
    'restore_standard_hex_viewer',
    'show_enhanced_hex_viewer',

    # Convenience aliases
    'show_hex_viewer',
    'integrate',
    'HexViewer',

    # Large file optimization (conditionally available)
    'LARGE_FILE_SUPPORT',
]

# Conditionally add large file components to __all__ if available
if LARGE_FILE_SUPPORT:
    __all__.extend([
        'LargeFileHandler',
        'MemoryConfig',
        'MemoryStrategy',
        'PerformanceMonitor',
        'PerformanceWidget',
    ])

# Convenience aliases
show_hex_viewer = show_enhanced_hex_viewer
integrate = integrate_with_intellicrack

# Main hex viewer class (alias for compatibility)
HexViewer = HexViewerWidget
