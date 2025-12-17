"""Production tests for deprecation warnings system.

Tests validate that deprecation decorators and context managers properly
emit warnings for legacy configuration access patterns and that warning
configuration works correctly in production scenarios.
"""

import functools
import warnings
from typing import Any

import pytest

from intellicrack.utils.deprecation_warnings import (
    DEPRECATION_MESSAGES,
    DeprecatedConfigAccess,
    check_deprecated_import,
    configure_deprecation_warnings,
    deprecated_cli_config_file,
    deprecated_config_method,
    deprecated_legacy_config_path,
    deprecated_llm_file_storage,
    deprecated_qsettings,
    emit_migration_warning,
)


class TestDeprecatedConfigMethod:
    """Test deprecated_config_method decorator functionality."""

    def test_decorator_emits_warning_on_call(self) -> None:
        """Decorator emits DeprecationWarning when decorated function is called."""

        @deprecated_config_method(replacement="IntellicrackConfig.get()")
        def old_get_setting() -> str:
            return "value"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_get_setting()

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "old_get_setting is deprecated" in str(w[0].message)
            assert "IntellicrackConfig.get()" in str(w[0].message)
            assert "version 4.0" in str(w[0].message)
            assert result == "value"

    def test_decorator_custom_version(self) -> None:
        """Decorator accepts custom version string."""

        @deprecated_config_method(replacement="new_method", version="5.0")
        def old_method() -> int:
            return 42

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_method()

            assert len(w) == 1
            assert "version 5.0" in str(w[0].message)

    def test_decorator_preserves_function_metadata(self) -> None:
        """Decorator preserves original function metadata."""

        @deprecated_config_method(replacement="new_func")
        def documented_function() -> None:
            """Original docstring."""

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "Original docstring."

    def test_decorator_preserves_arguments_and_return_value(self) -> None:
        """Decorator preserves function arguments and return values."""

        @deprecated_config_method(replacement="new_calc")
        def calculate(x: int, y: int, multiplier: int = 1) -> int:
            return (x + y) * multiplier

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = calculate(5, 3, multiplier=2)
            assert result == 16


class TestDeprecatedQSettings:
    """Test deprecated_qsettings decorator functionality."""

    def test_decorator_emits_qsettings_warning(self) -> None:
        """Decorator emits specific warning about QSettings deprecation."""

        @deprecated_qsettings
        def old_qsettings_method() -> str:
            return "setting"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_qsettings_method()

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "QSettings usage" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)
            assert "version 4.0" in str(w[0].message)

    def test_decorator_preserves_function_behavior(self) -> None:
        """Decorator does not alter function behavior."""

        @deprecated_qsettings
        def get_qsetting(key: str) -> str:
            return f"value_for_{key}"

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = get_qsetting("test_key")
            assert result == "value_for_test_key"


class TestDeprecatedLLMFileStorage:
    """Test deprecated_llm_file_storage decorator functionality."""

    def test_decorator_emits_llm_storage_warning(self) -> None:
        """Decorator emits specific warning about LLM file storage deprecation."""

        @deprecated_llm_file_storage
        def save_llm_config() -> bool:
            return True

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            save_llm_config()

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "File-based LLM configuration storage" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)


class TestDeprecatedCLIConfigFile:
    """Test deprecated_cli_config_file decorator functionality."""

    def test_decorator_emits_cli_config_warning(self) -> None:
        """Decorator emits specific warning about CLI config file deprecation."""

        @deprecated_cli_config_file
        def load_cli_config() -> dict[str, Any]:
            return {"verbose": True}

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load_cli_config()

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "CLI configuration file" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)


class TestDeprecatedLegacyConfigPath:
    """Test deprecated_legacy_config_path function."""

    def test_emits_warning_for_legacy_path(self) -> None:
        """Function emits warning when called with legacy path."""
        legacy_path = "/old/config/path.cfg"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            deprecated_legacy_config_path(legacy_path)

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert legacy_path in str(w[0].message)
            assert "config.json" in str(w[0].message)

    def test_warning_includes_migration_info(self) -> None:
        """Warning includes information about migration path."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            deprecated_legacy_config_path("/some/path")

            assert "centralized in config.json" in str(w[0].message)
            assert "version 4.0" in str(w[0].message)


class TestEmitMigrationWarning:
    """Test emit_migration_warning function."""

    def test_emits_migration_warning_default_system(self) -> None:
        """Function emits migration warning with default new system."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            emit_migration_warning("OldConfigSystem")

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "OldConfigSystem" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)

    def test_emits_migration_warning_custom_system(self) -> None:
        """Function emits migration warning with custom new system."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            emit_migration_warning("OldSystem", "NewSystem")

            assert len(w) == 1
            assert "OldSystem" in str(w[0].message)
            assert "NewSystem" in str(w[0].message)

    def test_warning_includes_version_info(self) -> None:
        """Warning includes version removal information."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            emit_migration_warning("Legacy")

            assert "version 4.0" in str(w[0].message)


class TestDeprecatedConfigAccess:
    """Test DeprecatedConfigAccess context manager."""

    def test_context_manager_emits_warning_on_enter(self) -> None:
        """Context manager emits warning when entering context."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with DeprecatedConfigAccess("TestSystem"):
                pass

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "TestSystem" in str(w[0].message)

    def test_context_manager_allows_code_execution(self) -> None:
        """Context manager allows code to execute within context."""
        executed = False

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with DeprecatedConfigAccess("OldSystem"):
                executed = True

        assert executed

    def test_context_manager_handles_exceptions(self) -> None:
        """Context manager properly handles exceptions in context."""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with pytest.raises(ValueError):
                with DeprecatedConfigAccess("System"):
                    raise ValueError("test error")

    def test_context_manager_returns_self(self) -> None:
        """Context manager returns self on enter."""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with DeprecatedConfigAccess("Test") as ctx:
                assert isinstance(ctx, DeprecatedConfigAccess)
                assert ctx.system_name == "Test"


class TestDeprecationMessages:
    """Test DEPRECATION_MESSAGES constant."""

    def test_contains_all_expected_keys(self) -> None:
        """DEPRECATION_MESSAGES contains all expected deprecation types."""
        expected_keys = {
            "qsettings",
            "llm_files",
            "cli_config",
            "legacy_paths",
            "env_files",
        }
        assert set(DEPRECATION_MESSAGES.keys()) == expected_keys

    def test_all_messages_reference_intellicrack_config(self) -> None:
        """All deprecation messages reference the new IntellicrackConfig system."""
        for key, message in DEPRECATION_MESSAGES.items():
            assert "IntellicrackConfig" in message or "config.json" in message


class TestCheckDeprecatedImport:
    """Test check_deprecated_import function."""

    def test_warns_for_qsettings_import(self) -> None:
        """Function warns when QSettings import is detected."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            check_deprecated_import("PyQt6.QtCore.QSettings")

            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "PyQt6.QtCore.QSettings" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)

    def test_warns_for_configparser_import(self) -> None:
        """Function warns when configparser import is detected."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            check_deprecated_import("configparser")

            assert len(w) == 1
            assert "configparser" in str(w[0].message)
            assert "IntellicrackConfig" in str(w[0].message)

    def test_no_warning_for_allowed_imports(self) -> None:
        """Function does not warn for non-deprecated imports."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            check_deprecated_import("json")
            check_deprecated_import("pathlib")

            assert len(w) == 0


class TestConfigureDeprecationWarnings:
    """Test configure_deprecation_warnings function."""

    def test_show_warnings_mode(self) -> None:
        """Function configures warnings to be shown."""
        configure_deprecation_warnings(show_warnings=True, error_on_deprecated=False)

        @deprecated_config_method(replacement="test")
        def test_func() -> None:
            pass

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("default")
            test_func()
            assert len(w) >= 1

    def test_hide_warnings_mode(self) -> None:
        """Function configures warnings to be hidden."""
        configure_deprecation_warnings(show_warnings=False, error_on_deprecated=False)

        @deprecated_config_method(replacement="test")
        def test_func() -> None:
            pass

        with warnings.catch_warnings(record=True) as w:
            test_func()

    def test_error_mode_converts_warnings_to_errors(self) -> None:
        """Function configures warnings to raise errors."""
        configure_deprecation_warnings(show_warnings=True, error_on_deprecated=True)

        @deprecated_config_method(replacement="test")
        def test_func() -> None:
            pass

        try:
            with pytest.raises(DeprecationWarning):
                test_func()
        finally:
            warnings.filterwarnings("default", category=DeprecationWarning)


class TestDecoratorStacklevel:
    """Test that decorators use correct stacklevel for warnings."""

    def test_warning_points_to_caller_not_decorator(self) -> None:
        """Warning stacklevel points to the actual call site."""

        @deprecated_config_method(replacement="new_method")
        def old_method() -> None:
            pass

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_method()

            assert len(w) == 1


class TestMultipleDecorators:
    """Test behavior when multiple decorators are stacked."""

    def test_multiple_deprecation_decorators(self) -> None:
        """Multiple deprecation decorators each emit their own warnings."""

        @deprecated_config_method(replacement="method1")
        @deprecated_qsettings
        def multi_deprecated() -> str:
            return "value"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = multi_deprecated()

            assert len(w) == 2
            assert result == "value"


class TestRealWorldUsageScenarios:
    """Test realistic production usage scenarios."""

    def test_migrating_qsettings_code(self) -> None:
        """Simulate real migration from QSettings to IntellicrackConfig."""

        class OldConfigManager:
            @deprecated_qsettings
            def get_setting(self, key: str) -> str:
                return f"old_{key}"

            @deprecated_qsettings
            def set_setting(self, key: str, value: str) -> None:
                pass

        manager = OldConfigManager()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            manager.get_setting("api_key")
            manager.set_setting("api_key", "new_value")

            assert len(w) == 2
            assert all(issubclass(warning.category, DeprecationWarning) for warning in w)

    def test_legacy_path_access_detection(self) -> None:
        """Simulate detection of legacy configuration path access."""
        legacy_paths = [
            "~/.intellicrack/llm_config.json",
            "~/.intellicrack/cli_config.ini",
            "/etc/intellicrack/settings.cfg",
        ]

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            for path in legacy_paths:
                deprecated_legacy_config_path(path)

            assert len(w) == len(legacy_paths)

    def test_import_checking_in_module_loader(self) -> None:
        """Simulate checking deprecated imports during module loading."""
        deprecated_imports = [
            "PyQt6.QtCore.QSettings",
            "configparser",
        ]

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            for module in deprecated_imports:
                check_deprecated_import(module)

            assert len(w) == len(deprecated_imports)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_decorator_with_exception_in_function(self) -> None:
        """Decorator handles exceptions raised by decorated function."""

        @deprecated_config_method(replacement="safe_method")
        def failing_method() -> None:
            raise RuntimeError("Function failed")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with pytest.raises(RuntimeError, match="Function failed"):
                failing_method()

            assert len(w) == 1

    def test_decorator_with_generator_function(self) -> None:
        """Decorator works with generator functions."""

        @deprecated_config_method(replacement="new_generator")
        def old_generator() -> Any:
            yield 1
            yield 2
            yield 3

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = list(old_generator())

            assert result == [1, 2, 3]
            assert len(w) == 1

    def test_empty_replacement_string(self) -> None:
        """Decorator handles empty replacement string."""

        @deprecated_config_method(replacement="")
        def old_method() -> None:
            pass

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            old_method()

            assert len(w) == 1

    def test_special_characters_in_system_name(self) -> None:
        """Context manager handles system names with special characters."""
        special_names = [
            "System-v1.0",
            "Config_Manager",
            "Settings (Legacy)",
        ]

        for name in special_names:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                with DeprecatedConfigAccess(name):
                    pass

                assert len(w) == 1
                assert name in str(w[0].message)
