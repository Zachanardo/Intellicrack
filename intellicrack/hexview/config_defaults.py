"""Hex Viewer Default Configuration Module.

This module defines all default configuration values for the Intellicrack Hex Viewer.
These defaults are merged into the main configuration system to provide sensible
fallback values when user customization is not present.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Any

HEX_VIEWER_DEFAULTS: dict[str, dict[str, Any]] = {
    "ui": {
        # Color Configuration
        "bg_color": "#1E1E1E",  # Dark background for reduced eye strain
        "text_color": "#D4D4D4",  # Light gray text for contrast
        "address_color": "#608B4E",  # Green for addresses
        "hex_color": "#D4D4D4",  # Default hex value color
        "ascii_color": "#CE9178",  # Orange-ish for ASCII representation
        "selection_bg_color": "#264F78",  # Blue selection background
        "selection_text_color": "#FFFFFF",  # White text on selection
        "modified_color": "#D16969",  # Red for modified bytes
        "highlight_color": "#FFD700",  # Gold for search highlights
        "cursor_color": "#AEAFAD",  # Gray cursor
        "grid_line_color": "#3C3C3C",  # Subtle grid lines
        # Font Configuration
        "font_family": "Consolas",  # Monospace font for hex display
        "font_size": 11,  # Default font size in points
        "font_weight": "normal",  # Font weight (normal, bold)
        "address_font_family": "Consolas",  # Font for address column
        "address_font_size": 11,
        # Layout Configuration
        "bytes_per_row": 16,  # Standard hex viewer row width
        "group_size": 1,  # Bytes per group (1, 2, 4, 8)
        "address_width": 8,  # Width of address display in hex digits
        "show_address": True,  # Show address column
        "show_hex": True,  # Show hex values
        "show_ascii": True,  # Show ASCII representation
        "show_grid_lines": False,  # Show grid lines between bytes
        "uppercase_hex": True,  # Display hex values in uppercase
        # Spacing Configuration
        "byte_spacing": 1,  # Pixels between bytes
        "group_spacing": 8,  # Pixels between groups
        "column_spacing": 16,  # Pixels between columns
        "row_height": 20,  # Height of each row in pixels
        "margin_left": 10,  # Left margin
        "margin_right": 10,  # Right margin
        "margin_top": 10,  # Top margin
        "margin_bottom": 10,  # Bottom margin
        # Scrollbar Configuration
        "scrollbar_width": 17,  # Width of vertical scrollbar
        "scrollbar_style": "system",  # system, minimal, or custom
        # Status Bar Configuration
        "show_status_bar": True,  # Show status bar
        "status_bar_height": 25,  # Height of status bar
        "show_offset_info": True,  # Show current offset in status
        "show_selection_info": True,  # Show selection size in status
        "show_file_size": True,  # Show file size in status
        "show_edit_mode": True,  # Show insert/overwrite mode
        # Tool Tips Configuration
        "show_tooltips": True,  # Enable tooltips
        "tooltip_delay_ms": 500,  # Tooltip display delay
        # Theme Presets
        "theme": "dark",  # dark, light, or custom
    },
    "performance": {
        # Memory Management
        "max_memory_mb": 500,  # Maximum memory usage in MB
        "chunk_size_kb": 64,  # Size of chunks for file reading
        "cache_size_mb": 100,  # Size of read cache
        "prefetch_chunks": 3,  # Number of chunks to prefetch
        "lazy_load": True,  # Enable lazy loading for large files
        # Rendering Performance
        "max_render_rows": 100,  # Maximum rows to render at once
        "render_buffer_rows": 20,  # Extra rows to render off-screen
        "smooth_scrolling": True,  # Enable smooth scrolling
        "scroll_speed_factor": 1.0,  # Scroll speed multiplier
        "animation_duration_ms": 150,  # Animation duration
        # File Operations
        "auto_save_interval_sec": 0,  # Auto-save interval (0 = disabled)
        "backup_on_save": True,  # Create backup before saving
        "use_memory_mapping": True,  # Use memory-mapped files
        "async_file_operations": True,  # Asynchronous file I/O
        # Search Performance
        "search_chunk_size_kb": 256,  # Chunk size for searching
        "search_threads": 4,  # Number of search threads
        "search_cache_results": True,  # Cache search results
        "max_search_results": 10000,  # Maximum search results to store
        # Undo/Redo Configuration
        "max_undo_history": 1000,  # Maximum undo operations
        "undo_memory_limit_mb": 50,  # Memory limit for undo buffer
        "compress_undo_data": True,  # Compress undo data
    },
    "search": {
        # Search History
        "history_max_entries": 50,  # Maximum search history entries
        "history_persistent": True,  # Save history between sessions
        "history_deduplicate": True,  # Remove duplicate entries
        # Search Options Defaults
        "case_sensitive": False,  # Case-sensitive search default
        "whole_word": False,  # Whole word search default
        "use_regex": False,  # Regular expression search default
        "wrap_around": True,  # Wrap around at end of file
        # Search Types
        "search_hex": True,  # Enable hex search
        "search_text": True,  # Enable text search
        "search_unicode": True,  # Enable Unicode search
        "search_pattern": True,  # Enable pattern/wildcard search
        # Advanced Search
        "parallel_search": True,  # Use parallel search
        "incremental_search": True,  # Search as you type
        "highlight_all_matches": True,  # Highlight all matches
        "max_highlight_matches": 100,  # Maximum matches to highlight
        # Replace Options
        "confirm_replace": True,  # Confirm before replace
        "preserve_file_size": False,  # Maintain file size on replace
        "backup_before_replace": True,  # Backup before replace all
    },
    "editing": {
        # Edit Modes
        "default_edit_mode": "overwrite",  # insert or overwrite
        "allow_insert_mode": True,  # Allow insert mode
        "allow_delete": True,  # Allow delete operations
        # Edit Validation
        "validate_hex_input": True,  # Validate hex input
        "auto_complete_hex": True,  # Auto-complete hex values
        "confirm_large_edits": True,  # Confirm large edit operations
        "large_edit_threshold_kb": 100,  # Threshold for large edits
        # Clipboard
        "clipboard_format": "hex",  # hex, text, or binary
        "include_address_in_copy": False,  # Include address in copy
        "smart_paste": True,  # Smart paste detection
    },
    "display": {
        # View Modes
        "default_view_mode": "hex_ascii",  # hex_ascii, hex_only, ascii_only
        "allow_view_switching": True,  # Allow view mode switching
        # Data Interpretation
        "show_data_inspector": True,  # Show data inspector panel
        "inspector_position": "right",  # left, right, bottom, or float
        "inspector_width": 250,  # Width of inspector panel
        "auto_detect_encoding": True,  # Auto-detect text encoding
        "default_encoding": "utf-8",  # Default text encoding
        # Highlighting
        "syntax_highlighting": True,  # Enable syntax highlighting
        "highlight_modifications": True,  # Highlight modified bytes
        "highlight_selection": True,  # Highlight selected bytes
        "highlight_patterns": True,  # Highlight detected patterns
    },
    "integration": {
        # Protection Viewer Integration
        "sync_with_protection_viewer": True,  # Enable synchronization
        "sync_delay_ms": 100,  # Synchronization delay
        "bidirectional_sync": True,  # Two-way synchronization
        # AI Integration
        "ai_analysis_enabled": True,  # Enable AI analysis
        "ai_auto_analyze": False,  # Auto-analyze on file open
        "ai_analysis_threshold_kb": 10,  # Min size for AI analysis
        "ai_model_preference": "auto",  # auto, local, or cloud
        "ai_cache_results": True,  # Cache AI analysis results
        # External Tools
        "external_diff_tool": "",  # Path to external diff tool
        "external_editor": "",  # Path to external editor
        "allow_external_edits": False,  # Allow external modifications
    },
    "shortcuts": {
        # File Operations
        "open_file": "Ctrl+O",
        "save_file": "Ctrl+S",
        "save_as": "Ctrl+Shift+S",
        "close_file": "Ctrl+W",
        # Edit Operations
        "undo": "Ctrl+Z",
        "redo": "Ctrl+Y",
        "cut": "Ctrl+X",
        "copy": "Ctrl+C",
        "paste": "Ctrl+V",
        "select_all": "Ctrl+A",
        # Search Operations
        "find": "Ctrl+F",
        "find_next": "F3",
        "find_previous": "Shift+F3",
        "replace": "Ctrl+H",
        "goto": "Ctrl+G",
        # View Operations
        "zoom_in": "Ctrl++",
        "zoom_out": "Ctrl+-",
        "zoom_reset": "Ctrl+0",
        "toggle_view_mode": "Tab",
        # Navigation
        "page_up": "PageUp",
        "page_down": "PageDown",
        "home": "Home",
        "end": "End",
        "goto_start": "Ctrl+Home",
        "goto_end": "Ctrl+End",
    },
    "advanced": {
        # Debug Options
        "debug_mode": False,  # Enable debug mode
        "log_level": "INFO",  # DEBUG, INFO, WARNING, ERROR
        "log_file": "",  # Path to log file
        # Experimental Features
        "enable_experimental": False,  # Enable experimental features
        "beta_features": [],  # List of beta features to enable
        # Plugin Support
        "enable_plugins": False,  # Enable plugin system
        "plugin_directory": "",  # Plugin directory path
        "auto_load_plugins": False,  # Auto-load plugins on start
    },
}
