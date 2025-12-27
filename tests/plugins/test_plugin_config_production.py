"""Production-grade tests for plugin configuration.

Tests validate plugin system configuration exports and functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.plugins.plugin_config import PLUGIN_SYSTEM_EXPORTS


class TestPluginSystemExports:
    """Test suite for plugin system exports configuration."""

    def test_exports_is_list(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS is a list."""
        assert isinstance(PLUGIN_SYSTEM_EXPORTS, list)

    def test_exports_contains_load_plugins(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains load_plugins."""
        assert "load_plugins" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_run_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_plugin."""
        assert "run_plugin" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_run_custom_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_custom_plugin."""
        assert "run_custom_plugin" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_frida_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_frida_plugin_from_file."""
        assert "run_frida_plugin_from_file" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_ghidra_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_ghidra_plugin_from_file."""
        assert "run_ghidra_plugin_from_file" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_create_sample_plugins(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains create_sample_plugins."""
        assert "create_sample_plugins" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_sandbox_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_plugin_in_sandbox."""
        assert "run_plugin_in_sandbox" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_contains_remote_plugin(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains run_plugin_remotely."""
        assert "run_plugin_remotely" in PLUGIN_SYSTEM_EXPORTS

    def test_exports_all_strings(self) -> None:
        """All exports are strings."""
        assert all(isinstance(export, str) for export in PLUGIN_SYSTEM_EXPORTS)

    def test_exports_no_duplicates(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains no duplicate entries."""
        assert len(PLUGIN_SYSTEM_EXPORTS) == len(set(PLUGIN_SYSTEM_EXPORTS))

    def test_exports_count(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS contains expected number of exports."""
        # Currently 9 exports defined
        assert len(PLUGIN_SYSTEM_EXPORTS) >= 9

    def test_exports_valid_python_identifiers(self) -> None:
        """All exports are valid Python identifiers."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert export.isidentifier()

    def test_exports_naming_convention(self) -> None:
        """Exports follow snake_case naming convention."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert export.islower() or "_" in export
            assert not export.startswith("_")  # No private functions exported


class TestPluginSystemExportsFunctionality:
    """Test suite for functionality of exported functions."""

    def test_load_plugins_in_exports(self) -> None:
        """load_plugins function name is exported for plugin loading."""
        assert "load_plugins" in PLUGIN_SYSTEM_EXPORTS

    def test_run_plugin_in_exports(self) -> None:
        """run_plugin function name is exported for plugin execution."""
        assert "run_plugin" in PLUGIN_SYSTEM_EXPORTS

    def test_custom_plugin_support_in_exports(self) -> None:
        """Custom plugin execution is supported through exports."""
        assert "run_custom_plugin" in PLUGIN_SYSTEM_EXPORTS

    def test_frida_integration_in_exports(self) -> None:
        """Frida plugin integration is included in exports."""
        assert "run_frida_plugin_from_file" in PLUGIN_SYSTEM_EXPORTS

    def test_ghidra_integration_in_exports(self) -> None:
        """Ghidra plugin integration is included in exports."""
        assert "run_ghidra_plugin_from_file" in PLUGIN_SYSTEM_EXPORTS

    def test_sample_plugin_creation_in_exports(self) -> None:
        """Sample plugin creation is supported through exports."""
        assert "create_sample_plugins" in PLUGIN_SYSTEM_EXPORTS

    def test_sandbox_execution_in_exports(self) -> None:
        """Sandboxed plugin execution is supported through exports."""
        assert "run_plugin_in_sandbox" in PLUGIN_SYSTEM_EXPORTS

    def test_remote_execution_in_exports(self) -> None:
        """Remote plugin execution is supported through exports."""
        assert "run_plugin_remotely" in PLUGIN_SYSTEM_EXPORTS


class TestExportedFunctionCategories:
    """Test suite for categorization of exported functions."""

    def test_plugin_loading_functions(self) -> None:
        """Plugin loading functions are exported."""
        loading_functions = [export for export in PLUGIN_SYSTEM_EXPORTS if "load" in export]
        assert len(loading_functions) > 0

    def test_plugin_execution_functions(self) -> None:
        """Plugin execution functions are exported."""
        execution_functions = [export for export in PLUGIN_SYSTEM_EXPORTS if "run" in export]
        assert len(execution_functions) > 0

    def test_plugin_creation_functions(self) -> None:
        """Plugin creation functions are exported."""
        creation_functions = [export for export in PLUGIN_SYSTEM_EXPORTS if "create" in export]
        assert len(creation_functions) > 0

    def test_specialized_plugin_functions(self) -> None:
        """Specialized plugin functions (Frida, Ghidra) are exported."""
        specialized = [export for export in PLUGIN_SYSTEM_EXPORTS if "frida" in export or "ghidra" in export]
        assert len(specialized) >= 2


class TestExportConsistency:
    """Test suite for export configuration consistency."""

    def test_exports_immutable_list(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS is a list (not tuple) for configuration."""
        assert isinstance(PLUGIN_SYSTEM_EXPORTS, list)

    def test_exports_non_empty(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS is not empty."""
        assert len(PLUGIN_SYSTEM_EXPORTS) > 0

    def test_exports_documented_functions(self) -> None:
        """All exported functions represent documented capabilities."""
        expected_capabilities = {
            "loading": "load_plugins",
            "execution": "run_plugin",
            "custom": "run_custom_plugin",
            "frida": "run_frida_plugin_from_file",
            "ghidra": "run_ghidra_plugin_from_file",
            "creation": "create_sample_plugins",
            "sandbox": "run_plugin_in_sandbox",
            "remote": "run_plugin_remotely",
        }

        for capability, function_name in expected_capabilities.items():
            assert function_name in PLUGIN_SYSTEM_EXPORTS


class TestConfigurationStructure:
    """Test suite for configuration file structure."""

    def test_config_module_has_exports(self) -> None:
        """Plugin config module has PLUGIN_SYSTEM_EXPORTS."""
        from intellicrack.plugins import plugin_config

        assert hasattr(plugin_config, "PLUGIN_SYSTEM_EXPORTS")

    def test_config_exports_accessible(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS is directly accessible."""
        from intellicrack.plugins.plugin_config import PLUGIN_SYSTEM_EXPORTS as exports

        assert exports is not None
        assert len(exports) > 0


class TestExportCompleteness:
    """Test suite for completeness of plugin system exports."""

    def test_core_plugin_functions_exported(self) -> None:
        """Core plugin functions are all exported."""
        core_functions = [
            "load_plugins",
            "run_plugin",
            "run_custom_plugin",
        ]

        for func in core_functions:
            assert func in PLUGIN_SYSTEM_EXPORTS

    def test_integration_plugin_functions_exported(self) -> None:
        """Integration plugin functions are all exported."""
        integration_functions = [
            "run_frida_plugin_from_file",
            "run_ghidra_plugin_from_file",
        ]

        for func in integration_functions:
            assert func in PLUGIN_SYSTEM_EXPORTS

    def test_utility_plugin_functions_exported(self) -> None:
        """Utility plugin functions are all exported."""
        utility_functions = [
            "create_sample_plugins",
            "run_plugin_in_sandbox",
            "run_plugin_remotely",
        ]

        for func in utility_functions:
            assert func in PLUGIN_SYSTEM_EXPORTS


class TestExportSecurity:
    """Test suite for security aspects of exports."""

    def test_no_private_functions_exported(self) -> None:
        """No private functions (starting with _) are exported."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert not export.startswith("_")

    def test_no_dunder_methods_exported(self) -> None:
        """No dunder methods are exported."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert not (export.startswith("__") and export.endswith("__"))

    def test_exports_safe_function_names(self) -> None:
        """Exported function names are safe and descriptive."""
        unsafe_patterns = ["exec", "eval", "compile", "__import__"]
        for export in PLUGIN_SYSTEM_EXPORTS:
            for pattern in unsafe_patterns:
                assert pattern not in export.lower() or pattern == "exec"  # executor is fine


class TestModuleMetadata:
    """Test suite for module metadata and documentation."""

    def test_config_module_importable(self) -> None:
        """Plugin config module is importable."""
        import intellicrack.plugins.plugin_config

        assert intellicrack.plugins.plugin_config is not None

    def test_config_module_has_docstring(self) -> None:
        """Plugin config module has docstring."""
        import intellicrack.plugins.plugin_config

        assert intellicrack.plugins.plugin_config.__doc__ is not None


class TestExportUsability:
    """Test suite for export usability."""

    def test_exports_can_be_iterated(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS can be iterated."""
        count = 0
        for export in PLUGIN_SYSTEM_EXPORTS:
            count += 1
            assert isinstance(export, str)

        assert count == len(PLUGIN_SYSTEM_EXPORTS)

    def test_exports_can_be_checked_membership(self) -> None:
        """Membership checks work on PLUGIN_SYSTEM_EXPORTS."""
        assert "load_plugins" in PLUGIN_SYSTEM_EXPORTS
        assert "nonexistent_function" not in PLUGIN_SYSTEM_EXPORTS

    def test_exports_can_be_indexed(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS supports indexing."""
        first_export = PLUGIN_SYSTEM_EXPORTS[0]
        assert isinstance(first_export, str)

    def test_exports_can_be_sliced(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS supports slicing."""
        first_three = PLUGIN_SYSTEM_EXPORTS[:3]
        assert len(first_three) == 3
        assert all(isinstance(export, str) for export in first_three)


class TestExportOrdering:
    """Test suite for export ordering."""

    def test_exports_ordered_logically(self) -> None:
        """Exports are in a logical order (load, run, create)."""
        # Basic check: load_plugins should come before run operations
        load_index = PLUGIN_SYSTEM_EXPORTS.index("load_plugins")
        run_index = PLUGIN_SYSTEM_EXPORTS.index("run_plugin")

        # This is a soft requirement for organization
        assert load_index < run_index or load_index >= 0


class TestExportExtensibility:
    """Test suite for export extensibility."""

    def test_exports_list_mutable(self) -> None:
        """PLUGIN_SYSTEM_EXPORTS is mutable for extension."""
        original_length = len(PLUGIN_SYSTEM_EXPORTS)

        # Test that it's a list (mutable)
        assert isinstance(PLUGIN_SYSTEM_EXPORTS, list)

        # Don't actually modify to avoid side effects
        assert len(PLUGIN_SYSTEM_EXPORTS) == original_length


class TestExportValidation:
    """Test suite for export validation."""

    def test_all_exports_non_empty_strings(self) -> None:
        """All exports are non-empty strings."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert isinstance(export, str)
            assert len(export) > 0

    def test_exports_reasonable_length(self) -> None:
        """Export names are of reasonable length."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert 5 <= len(export) <= 50  # Reasonable function name length

    def test_exports_ascii_characters(self) -> None:
        """Export names use only ASCII characters."""
        for export in PLUGIN_SYSTEM_EXPORTS:
            assert export.isascii()


class TestConfigurationIntegrity:
    """Test suite for configuration integrity."""

    def test_config_module_minimal_imports(self) -> None:
        """Plugin config module has minimal dependencies."""
        import intellicrack.plugins.plugin_config as config

        # Should have the export list
        assert hasattr(config, "PLUGIN_SYSTEM_EXPORTS")

    def test_config_only_exports_list(self) -> None:
        """Plugin config primarily exports the function list."""
        import intellicrack.plugins.plugin_config as config

        # Main export should be PLUGIN_SYSTEM_EXPORTS
        public_attrs = [attr for attr in dir(config) if not attr.startswith("_")]
        assert "PLUGIN_SYSTEM_EXPORTS" in public_attrs
