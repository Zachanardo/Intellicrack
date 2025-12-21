"""Production tests for hex viewer configuration defaults.

Tests validate configuration system integrity:
- All required configuration keys present
- Value types match expected types
- Ranges are sensible for production use
- Color values are valid hex codes
- Font specifications are usable
- Keyboard shortcuts don't conflict

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

import pytest

from intellicrack.hexview.config_defaults import HEX_VIEWER_DEFAULTS


class TestConfigurationStructure:
    """Test configuration structure and completeness."""

    def test_config_has_required_sections(self) -> None:
        """Configuration contains all required sections."""
        required_sections = [
            "ui",
            "performance",
            "search",
            "editing",
            "display",
            "integration",
            "shortcuts",
            "advanced",
        ]

        for section in required_sections:
            assert section in HEX_VIEWER_DEFAULTS
            assert isinstance(HEX_VIEWER_DEFAULTS[section], dict)

    def test_config_sections_not_empty(self) -> None:
        """All configuration sections have content."""
        for section_name, section_data in HEX_VIEWER_DEFAULTS.items():
            assert len(section_data) > 0


class TestUIConfiguration:
    """Test UI configuration section."""

    def test_ui_color_values_valid_hex(self) -> None:
        """UI color values are valid hex color codes."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        color_keys = [
            "bg_color",
            "text_color",
            "address_color",
            "hex_color",
            "ascii_color",
            "selection_bg_color",
            "selection_text_color",
            "modified_color",
            "highlight_color",
            "cursor_color",
            "grid_line_color",
        ]

        for key in color_keys:
            assert key in ui_config
            color = ui_config[key]
            assert isinstance(color, str)
            assert color.startswith("#")
            assert len(color) == 7
            assert all(c in "0123456789ABCDEFabcdef" for c in color[1:])

    def test_ui_font_configuration_valid(self) -> None:
        """UI font configuration has valid values."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        assert "font_family" in ui_config
        assert isinstance(ui_config["font_family"], str)
        assert len(ui_config["font_family"]) > 0

        assert "font_size" in ui_config
        assert isinstance(ui_config["font_size"], int)
        assert 8 <= ui_config["font_size"] <= 24

        assert "font_weight" in ui_config
        assert ui_config["font_weight"] in ("normal", "bold")

    def test_ui_layout_configuration_valid(self) -> None:
        """UI layout configuration has sensible values."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        assert "bytes_per_row" in ui_config
        assert ui_config["bytes_per_row"] in (8, 16, 32)

        assert "group_size" in ui_config
        assert ui_config["group_size"] in (1, 2, 4, 8)

        assert "address_width" in ui_config
        assert isinstance(ui_config["address_width"], int)
        assert ui_config["address_width"] >= 4

    def test_ui_visibility_flags_boolean(self) -> None:
        """UI visibility flags are boolean values."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        boolean_flags = [
            "show_address",
            "show_hex",
            "show_ascii",
            "show_grid_lines",
            "uppercase_hex",
            "show_status_bar",
            "show_tooltips",
        ]

        for flag in boolean_flags:
            assert flag in ui_config
            assert isinstance(ui_config[flag], bool)

    def test_ui_spacing_values_positive(self) -> None:
        """UI spacing values are positive integers."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        spacing_keys = [
            "byte_spacing",
            "group_spacing",
            "column_spacing",
            "row_height",
            "margin_left",
            "margin_right",
            "margin_top",
            "margin_bottom",
        ]

        for key in spacing_keys:
            assert key in ui_config
            assert isinstance(ui_config[key], int)
            assert ui_config[key] >= 0

    def test_ui_theme_valid(self) -> None:
        """UI theme setting has valid value."""
        ui_config = HEX_VIEWER_DEFAULTS["ui"]

        assert "theme" in ui_config
        assert ui_config["theme"] in ("dark", "light", "custom")


class TestPerformanceConfiguration:
    """Test performance configuration section."""

    def test_performance_memory_limits_sensible(self) -> None:
        """Performance memory limits are reasonable for production."""
        perf_config = HEX_VIEWER_DEFAULTS["performance"]

        assert "max_memory_mb" in perf_config
        assert 100 <= perf_config["max_memory_mb"] <= 2048

        assert "cache_size_mb" in perf_config
        assert 10 <= perf_config["cache_size_mb"] <= 500

        assert "undo_memory_limit_mb" in perf_config
        assert 10 <= perf_config["undo_memory_limit_mb"] <= 200

    def test_performance_chunk_sizes_valid(self) -> None:
        """Performance chunk sizes are appropriate."""
        perf_config = HEX_VIEWER_DEFAULTS["performance"]

        assert "chunk_size_kb" in perf_config
        assert 16 <= perf_config["chunk_size_kb"] <= 256

        assert "search_chunk_size_kb" in perf_config
        assert 64 <= perf_config["search_chunk_size_kb"] <= 1024

    def test_performance_rendering_limits_reasonable(self) -> None:
        """Performance rendering limits prevent UI freezing."""
        perf_config = HEX_VIEWER_DEFAULTS["performance"]

        assert "max_render_rows" in perf_config
        assert 50 <= perf_config["max_render_rows"] <= 1000

        assert "render_buffer_rows" in perf_config
        assert 10 <= perf_config["render_buffer_rows"] <= 100

    def test_performance_boolean_flags(self) -> None:
        """Performance optimization flags are boolean."""
        perf_config = HEX_VIEWER_DEFAULTS["performance"]

        boolean_flags = [
            "lazy_load",
            "smooth_scrolling",
            "backup_on_save",
            "use_memory_mapping",
            "async_file_operations",
            "search_cache_results",
            "compress_undo_data",
        ]

        for flag in boolean_flags:
            assert flag in perf_config
            assert isinstance(perf_config[flag], bool)

    def test_performance_thread_count_valid(self) -> None:
        """Performance thread counts are reasonable."""
        perf_config = HEX_VIEWER_DEFAULTS["performance"]

        assert "search_threads" in perf_config
        assert 1 <= perf_config["search_threads"] <= 16


class TestSearchConfiguration:
    """Test search configuration section."""

    def test_search_history_settings(self) -> None:
        """Search history configuration is valid."""
        search_config = HEX_VIEWER_DEFAULTS["search"]

        assert "history_max_entries" in search_config
        assert 10 <= search_config["history_max_entries"] <= 1000

        assert "history_persistent" in search_config
        assert isinstance(search_config["history_persistent"], bool)

        assert "history_deduplicate" in search_config
        assert isinstance(search_config["history_deduplicate"], bool)

    def test_search_option_defaults(self) -> None:
        """Search option defaults are boolean."""
        search_config = HEX_VIEWER_DEFAULTS["search"]

        boolean_options = [
            "case_sensitive",
            "whole_word",
            "use_regex",
            "wrap_around",
            "search_hex",
            "search_text",
            "search_unicode",
            "search_pattern",
            "parallel_search",
            "incremental_search",
            "highlight_all_matches",
        ]

        for option in boolean_options:
            assert option in search_config
            assert isinstance(search_config[option], bool)

    def test_search_performance_limits(self) -> None:
        """Search performance limits prevent hangs."""
        search_config = HEX_VIEWER_DEFAULTS["search"]

        assert "max_highlight_matches" in search_config
        assert 10 <= search_config["max_highlight_matches"] <= 10000


class TestEditingConfiguration:
    """Test editing configuration section."""

    def test_editing_mode_defaults(self) -> None:
        """Editing mode defaults are valid."""
        edit_config = HEX_VIEWER_DEFAULTS["editing"]

        assert "default_edit_mode" in edit_config
        assert edit_config["default_edit_mode"] in ("insert", "overwrite")

        assert "allow_insert_mode" in edit_config
        assert isinstance(edit_config["allow_insert_mode"], bool)

        assert "allow_delete" in edit_config
        assert isinstance(edit_config["allow_delete"], bool)

    def test_editing_validation_flags(self) -> None:
        """Editing validation flags are boolean."""
        edit_config = HEX_VIEWER_DEFAULTS["editing"]

        assert "validate_hex_input" in edit_config
        assert isinstance(edit_config["validate_hex_input"], bool)

        assert "auto_complete_hex" in edit_config
        assert isinstance(edit_config["auto_complete_hex"], bool)

    def test_editing_clipboard_format(self) -> None:
        """Editing clipboard format is valid."""
        edit_config = HEX_VIEWER_DEFAULTS["editing"]

        assert "clipboard_format" in edit_config
        assert edit_config["clipboard_format"] in ("hex", "text", "binary")


class TestDisplayConfiguration:
    """Test display configuration section."""

    def test_display_view_mode_valid(self) -> None:
        """Display view mode has valid value."""
        display_config = HEX_VIEWER_DEFAULTS["display"]

        assert "default_view_mode" in display_config
        assert display_config["default_view_mode"] in ("hex_ascii", "hex_only", "ascii_only")

    def test_display_inspector_configuration(self) -> None:
        """Display data inspector configuration is valid."""
        display_config = HEX_VIEWER_DEFAULTS["display"]

        assert "show_data_inspector" in display_config
        assert isinstance(display_config["show_data_inspector"], bool)

        assert "inspector_position" in display_config
        assert display_config["inspector_position"] in ("left", "right", "bottom", "float")

        assert "inspector_width" in display_config
        assert 100 <= display_config["inspector_width"] <= 500

    def test_display_encoding_settings(self) -> None:
        """Display encoding settings are valid."""
        display_config = HEX_VIEWER_DEFAULTS["display"]

        assert "auto_detect_encoding" in display_config
        assert isinstance(display_config["auto_detect_encoding"], bool)

        assert "default_encoding" in display_config
        assert isinstance(display_config["default_encoding"], str)


class TestIntegrationConfiguration:
    """Test integration configuration section."""

    def test_integration_protection_viewer_sync(self) -> None:
        """Integration protection viewer settings are valid."""
        integration_config = HEX_VIEWER_DEFAULTS["integration"]

        assert "sync_with_protection_viewer" in integration_config
        assert isinstance(integration_config["sync_with_protection_viewer"], bool)

        assert "sync_delay_ms" in integration_config
        assert 10 <= integration_config["sync_delay_ms"] <= 1000

        assert "bidirectional_sync" in integration_config
        assert isinstance(integration_config["bidirectional_sync"], bool)

    def test_integration_ai_settings(self) -> None:
        """Integration AI settings are valid."""
        integration_config = HEX_VIEWER_DEFAULTS["integration"]

        assert "ai_analysis_enabled" in integration_config
        assert isinstance(integration_config["ai_analysis_enabled"], bool)

        assert "ai_auto_analyze" in integration_config
        assert isinstance(integration_config["ai_auto_analyze"], bool)

        assert "ai_analysis_threshold_kb" in integration_config
        assert 1 <= integration_config["ai_analysis_threshold_kb"] <= 1024

        assert "ai_model_preference" in integration_config
        assert integration_config["ai_model_preference"] in ("auto", "local", "cloud")


class TestShortcutsConfiguration:
    """Test keyboard shortcuts configuration."""

    def test_shortcuts_all_defined(self) -> None:
        """All essential shortcuts are defined."""
        shortcuts_config = HEX_VIEWER_DEFAULTS["shortcuts"]

        essential_shortcuts = [
            "open_file",
            "save_file",
            "undo",
            "redo",
            "copy",
            "paste",
            "find",
            "find_next",
            "goto",
        ]

        for shortcut in essential_shortcuts:
            assert shortcut in shortcuts_config
            assert isinstance(shortcuts_config[shortcut], str)
            assert len(shortcuts_config[shortcut]) > 0

    def test_shortcuts_format_valid(self) -> None:
        """Shortcuts follow valid format."""
        shortcuts_config = HEX_VIEWER_DEFAULTS["shortcuts"]

        for shortcut_name, shortcut_value in shortcuts_config.items():
            assert isinstance(shortcut_value, str)
            parts = shortcut_value.split("+")
            for part in parts:
                assert part in ("Ctrl", "Alt", "Shift", "PageUp", "PageDown", "Home", "End", "Tab") or len(part) == 1 or part.startswith("F")

    def test_shortcuts_no_duplicates(self) -> None:
        """No duplicate shortcut definitions."""
        shortcuts_config = HEX_VIEWER_DEFAULTS["shortcuts"]

        shortcut_values = list(shortcuts_config.values())
        unique_shortcuts = set(shortcut_values)

        assert len(shortcut_values) == len(unique_shortcuts)


class TestAdvancedConfiguration:
    """Test advanced configuration section."""

    def test_advanced_debug_settings(self) -> None:
        """Advanced debug settings are valid."""
        advanced_config = HEX_VIEWER_DEFAULTS["advanced"]

        assert "debug_mode" in advanced_config
        assert isinstance(advanced_config["debug_mode"], bool)

        assert "log_level" in advanced_config
        assert advanced_config["log_level"] in ("DEBUG", "INFO", "WARNING", "ERROR")

    def test_advanced_plugin_settings(self) -> None:
        """Advanced plugin settings are valid."""
        advanced_config = HEX_VIEWER_DEFAULTS["advanced"]

        assert "enable_plugins" in advanced_config
        assert isinstance(advanced_config["enable_plugins"], bool)

        assert "auto_load_plugins" in advanced_config
        assert isinstance(advanced_config["auto_load_plugins"], bool)


class TestConfigurationIntegrity:
    """Test overall configuration integrity."""

    def test_config_type_consistency(self) -> None:
        """All config values have consistent types across sections."""
        for section_name, section_data in HEX_VIEWER_DEFAULTS.items():
            for key, value in section_data.items():
                assert value is not None
                assert type(value) in (str, int, float, bool, list)

    def test_config_no_placeholder_values(self) -> None:
        """Configuration has no placeholder or dummy values."""
        for section_name, section_data in HEX_VIEWER_DEFAULTS.items():
            for key, value in section_data.items():
                if isinstance(value, str):
                    assert value not in ("TODO", "FIXME", "PLACEHOLDER", "XXX")
                    if key.endswith("_color"):
                        assert value.startswith("#") or value == ""

    def test_config_defaults_suitable_for_license_cracking(self) -> None:
        """Configuration defaults are optimized for license cracking workflow."""
        assert HEX_VIEWER_DEFAULTS["integration"]["ai_analysis_enabled"] is True

        assert HEX_VIEWER_DEFAULTS["editing"]["allow_insert_mode"] is True
        assert HEX_VIEWER_DEFAULTS["editing"]["allow_delete"] is True

        assert HEX_VIEWER_DEFAULTS["search"]["search_hex"] is True
        assert HEX_VIEWER_DEFAULTS["search"]["search_pattern"] is True

        assert HEX_VIEWER_DEFAULTS["performance"]["use_memory_mapping"] is True
        assert HEX_VIEWER_DEFAULTS["performance"]["async_file_operations"] is True

    def test_config_memory_settings_sufficient_for_large_binaries(self) -> None:
        """Memory settings can handle large protected binaries."""
        perf = HEX_VIEWER_DEFAULTS["performance"]

        assert perf["max_memory_mb"] >= 500
        assert perf["cache_size_mb"] >= 100
        assert perf["chunk_size_kb"] >= 32

    def test_config_search_settings_effective_for_pattern_finding(self) -> None:
        """Search settings enable effective pattern finding."""
        search = HEX_VIEWER_DEFAULTS["search"]

        assert search["parallel_search"] is True
        assert search["highlight_all_matches"] is True
        assert search["search_hex"] is True
        assert search["search_text"] is True
        assert search["search_pattern"] is True

    def test_config_ui_settings_suitable_for_hex_analysis(self) -> None:
        """UI settings are optimized for hex analysis work."""
        ui = HEX_VIEWER_DEFAULTS["ui"]

        assert ui["show_address"] is True
        assert ui["show_hex"] is True
        assert ui["show_ascii"] is True
        assert ui["bytes_per_row"] in (16, 32)
        assert ui["uppercase_hex"] is True
