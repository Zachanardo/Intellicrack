"""
Enhanced Hex Viewer/Editor module for Intellicrack.

This module provides a feature-rich hex viewer and editor that:
- Can handle files of any size through memory mapping
- Integrates with the AI model
- Allows the AI to search/edit hex based on user input
- Provides multiple visualization modes

Usage:
    # Simple usage - show hex viewer for a file
    from Intellicrack.hexview import show_hex_viewer
    show_hex_viewer(file_path)

    # Integrate with Intellicrack
    from Intellicrack.hexview import integrate_with_intellicrack
    integrate_with_intellicrack(app_instance)

    # Work with binary data
    from Intellicrack.hexview import analyze_binary_data
    results = analyze_binary_data(data)
"""

# Core components
from .ai_bridge import AIBinaryBridge, BinaryContextBuilder

# API functions
from .api import (
    add_hex_viewer_to_application,
    # Analysis operations
    analyze_binary_data,
    # Utility operations
    bytes_to_hex_string,
    create_binary_context,
    create_hex_viewer_dialog,
    # UI operations
    create_hex_viewer_widget,
    hex_string_to_bytes,
    # Integration operations
    integrate_with_intellicrack,
    launch_hex_viewer,
    # File operations
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

# Large file optimization components
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
    LARGE_FILE_SUPPORT = True
except ImportError:
    LARGE_FILE_SUPPORT = False

# Integration functions
from .integration import (
    initialize_hex_viewer,
    integrate_enhanced_hex_viewer,
    register_hex_viewer_ai_tools,
    restore_standard_hex_viewer,
    show_enhanced_hex_viewer,
)

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
