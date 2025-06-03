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
    from .large_file_handler import LargeFileHandler, MemoryConfig, MemoryStrategy
    from .performance_monitor import PerformanceMonitor, PerformanceWidget
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

# Convenience aliases
show_hex_viewer = show_enhanced_hex_viewer
integrate = integrate_with_intellicrack
