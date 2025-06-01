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
from .file_handler import VirtualFileAccess, ChunkManager
from .hex_widget import HexViewerWidget
from .hex_renderer import HexViewRenderer, ViewMode, parse_hex_view
from .hex_highlighter import HexHighlighter, HighlightType
from .hex_dialog import HexViewerDialog
from .ai_bridge import AIBinaryBridge, BinaryContextBuilder

# Integration functions
from .integration import (
    show_enhanced_hex_viewer,
    integrate_enhanced_hex_viewer, 
    initialize_hex_viewer,
    restore_standard_hex_viewer,
    register_hex_viewer_ai_tools
)

# API functions
from .api import (
    # File operations
    open_hex_file,
    read_hex_region,
    write_hex_region,
    
    # Analysis operations
    analyze_binary_data,
    search_binary_pattern,
    suggest_binary_edits,
    
    # UI operations
    create_hex_viewer_widget,
    create_hex_viewer_dialog,
    launch_hex_viewer,
    
    # Integration operations
    integrate_with_intellicrack,
    add_hex_viewer_to_application,
    register_ai_tools,
    
    # Utility operations
    bytes_to_hex_string,
    hex_string_to_bytes,
    create_binary_context
)

# Convenience aliases
show_hex_viewer = show_enhanced_hex_viewer
integrate = integrate_with_intellicrack