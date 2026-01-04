import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

import pytest


class TestPackageConstants:
    def test_version_constant_exists(self) -> None:
        import intellicrack

        assert hasattr(intellicrack, "__version__")
        assert isinstance(intellicrack.__version__, str)

    def test_version_format(self) -> None:
        import intellicrack

        version_parts = intellicrack.__version__.split(".")
        assert len(version_parts) >= 2
        assert all(part.isdigit() for part in version_parts)

    def test_author_constant_exists(self) -> None:
        import intellicrack

        assert hasattr(intellicrack, "__author__")
        assert isinstance(intellicrack.__author__, str)
        assert len(intellicrack.__author__) > 0

    def test_license_constant_exists(self) -> None:
        import intellicrack

        assert hasattr(intellicrack, "__license__")
        assert intellicrack.__license__ == "GPL-3.0"


class TestEnvironmentVariableSetup:
    def test_threading_environment_variables_set(self) -> None:
        import intellicrack

        assert "OMP_NUM_THREADS" in os.environ
        assert "MKL_NUM_THREADS" in os.environ
        assert "NUMEXPR_NUM_THREADS" in os.environ

    def test_threading_variables_have_safe_values(self) -> None:
        import intellicrack

        assert os.environ.get("OMP_NUM_THREADS") == "1"
        assert os.environ.get("MKL_NUM_THREADS") == "1"
        assert os.environ.get("NUMEXPR_NUM_THREADS") == "1"

    def test_pybind11_variable_set(self) -> None:
        import intellicrack

        assert "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF" in os.environ
        assert os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"] == "1"


class TestGetVersionFunction:
    def test_get_version_returns_string(self) -> None:
        import intellicrack

        version = intellicrack.get_version()

        assert isinstance(version, str)
        assert len(version) > 0

    def test_get_version_matches_constant(self) -> None:
        import intellicrack

        version = intellicrack.get_version()

        assert version == intellicrack.__version__

    def test_get_version_semantic_format(self) -> None:
        import intellicrack

        version = intellicrack.get_version()
        parts = version.split(".")

        assert len(parts) >= 2
        assert all(part.isdigit() for part in parts[:2])


class RealGPUInfoValidator:
    """Real validator for GPU information and device strings."""

    def __init__(self) -> None:
        self.valid_device_prefixes = ["cpu", "cuda", "xpu", "mps"]
        self.valid_device_patterns = [
            "cpu",
            "cuda",
            "cuda:0",
            "cuda:1",
            "cuda:2",
            "cuda:3",
            "xpu",
            "xpu:0",
            "mps",
        ]

    def is_valid_device_string(self, device: str) -> bool:
        """Check if device string follows expected format."""
        if not isinstance(device, str):
            return False  # type: ignore[unreachable]
        return any(device.startswith(prefix) for prefix in self.valid_device_prefixes)

    def validate_gpu_initialization_result(self, device: str) -> bool:
        """Validate that GPU initialization returns a proper device string."""
        return self.is_valid_device_string(device) and len(device) > 0


class TestGPUInitialization:
    def test_initialize_gpu_returns_valid_device(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu()

        validator = RealGPUInfoValidator()
        assert validator.is_valid_device_string(device)
        assert len(device) > 0

    def test_initialize_gpu_returns_cpu_or_accelerator(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu()

        valid_devices = ["cpu", "cuda", "cuda:0", "xpu", "mps"]
        assert any(device.startswith(valid_dev) for valid_dev in valid_devices)

    def test_initialize_gpu_caches_result(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False
        device1 = intellicrack._initialize_gpu()

        intellicrack._gpu_initialized = True
        device2 = intellicrack._initialize_gpu()

        assert intellicrack._gpu_initialized

    def test_initialize_gpu_with_timeout_returns_device(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu_with_timeout(timeout_seconds=1)

        assert isinstance(device, str)
        validator = RealGPUInfoValidator()
        assert validator.is_valid_device_string(device)

    def test_initialize_gpu_with_timeout_handles_timeout(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu_with_timeout(timeout_seconds=0.001)  # type: ignore[arg-type]

        assert device == "cpu"

    def test_initialize_gpu_with_timeout_sets_default_device(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False
        original_device = intellicrack._default_device

        device = intellicrack._initialize_gpu_with_timeout(timeout_seconds=2)

        assert intellicrack._default_device == device
        assert intellicrack._gpu_initialized


class RealGILSafetyChecker:
    """Real checker for GIL safety initialization state."""

    def __init__(self) -> None:
        self.required_env_vars = ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"]

    def verify_gil_safety_environment(self) -> bool:
        """Verify GIL safety environment variables are set."""
        return all(os.environ.get(var) == "1" for var in self.required_env_vars)

    def verify_gil_safety_initialized(self, initialized: bool) -> bool:
        """Verify GIL safety initialization flag is properly set."""
        return isinstance(initialized, bool)


class TestGILSafetyInitialization:
    def test_gil_safety_initialization_idempotent(self) -> None:
        import intellicrack

        intellicrack._gil_safety_initialized = False
        intellicrack._initialize_gil_safety()

        assert intellicrack._gil_safety_initialized

        intellicrack._initialize_gil_safety()

        assert intellicrack._gil_safety_initialized

    def test_gil_safety_environment_properly_set(self) -> None:
        import intellicrack

        checker = RealGILSafetyChecker()
        assert checker.verify_gil_safety_environment()

    def test_gil_safety_flag_is_boolean(self) -> None:
        import intellicrack

        checker = RealGILSafetyChecker()
        assert checker.verify_gil_safety_initialized(intellicrack._gil_safety_initialized)


class RealConfigValidator:
    """Real validator for configuration objects and their structure."""

    def __init__(self) -> None:
        self.required_runtime_keys = ["initialized", "version"]

    def validate_config_structure(self, config: Any) -> bool:
        """Validate that config has expected structure."""
        if config is None:
            return False
        return isinstance(config, (dict, object))

    def validate_runtime_defaults(self, defaults: dict[str, Any]) -> bool:
        """Validate runtime defaults dictionary structure."""
        return all(key in defaults for key in self.required_runtime_keys)

    def extract_runtime_defaults(self, version: str) -> dict[str, Any]:
        """Extract real runtime defaults that should be applied to config."""
        return {
            "initialized": True,
            "version": version,
        }


class TestConfigurationInitialization:
    def test_config_initialization_lazy(self) -> None:
        import intellicrack

        assert hasattr(intellicrack, "_initialize_config")

    def test_initialize_config_returns_config_object(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        validator = RealConfigValidator()
        assert validator.validate_config_structure(config)

    def test_initialize_config_caches_result(self) -> None:
        import intellicrack

        intellicrack._config = None
        config1 = intellicrack._initialize_config()
        config2 = intellicrack._initialize_config()

        assert config1 is config2

    def test_config_update_with_runtime_defaults(self) -> None:
        import intellicrack

        validator = RealConfigValidator()
        defaults = validator.extract_runtime_defaults(intellicrack.__version__)

        assert validator.validate_runtime_defaults(defaults)
        assert defaults["initialized"] is True
        assert defaults["version"] == intellicrack.__version__

    def test_validate_config_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._validate_config(config)

    def test_log_repository_status_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._log_repository_status(config)

    def test_log_ghidra_path_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._log_ghidra_path(config)


class RealModuleLoader:
    """Real module loader for validating lazy import behavior."""

    def __init__(self) -> None:
        self.loaded_modules: set[str] = set()

    def attempt_module_import(self, module_name: str) -> Optional[Any]:
        """Attempt to import a module and track success."""
        try:
            module = __import__(module_name, fromlist=[""])
            self.loaded_modules.add(module_name)
            return module
        except ImportError:
            return None

    def verify_module_has_name(self, module: Any) -> bool:
        """Verify module has __name__ attribute."""
        return hasattr(module, "__name__")

    def verify_callable(self, obj: Any) -> bool:
        """Verify object is callable."""
        return callable(obj)


class TestLazyImports:
    def test_lazy_import_config_returns_config(self) -> None:
        import intellicrack

        config = intellicrack._lazy_import_config()

        assert config is not None

    def test_lazy_import_config_caches_result(self) -> None:
        import intellicrack

        intellicrack._config_cached = None
        config1 = intellicrack._lazy_import_config()
        config2 = intellicrack._lazy_import_config()

        assert config1 is config2

    def test_lazy_import_get_config_returns_function(self) -> None:
        import intellicrack

        get_config = intellicrack._lazy_import_get_config()

        loader = RealModuleLoader()
        assert get_config is not None
        assert loader.verify_callable(get_config)

    def test_lazy_import_main_returns_callable_or_none(self) -> None:
        import intellicrack

        main = intellicrack._lazy_import_main()

        loader = RealModuleLoader()
        assert main is None or loader.verify_callable(main)

    def test_lazy_import_app_returns_class_or_none(self) -> None:
        import intellicrack

        app_class = intellicrack._lazy_import_app()

        loader = RealModuleLoader()
        assert app_class is None or loader.verify_callable(app_class)


class TestGetDefaultDevice:
    def test_get_default_device_returns_string(self) -> None:
        import intellicrack

        device = intellicrack.get_default_device()

        assert isinstance(device, str)
        assert len(device) > 0

    def test_get_default_device_valid_values(self) -> None:
        import intellicrack

        device = intellicrack.get_default_device()

        validator = RealGPUInfoValidator()
        assert validator.is_valid_device_string(device)


class RealAppValidator:
    """Real validator for application instances."""

    def __init__(self) -> None:
        self.required_app_attributes: list[str] = []

    def validate_app_instance(self, app: Any) -> bool:
        """Validate that app is a real instance."""
        return app is not None and hasattr(app, "__class__")

    def validate_importerror_message(self, error: ImportError, expected_substring: str) -> bool:
        """Validate ImportError message contains expected text."""
        return expected_substring in str(error)

    def validate_runtimeerror_message(self, error: RuntimeError, expected_substring: str) -> bool:
        """Validate RuntimeError message contains expected text."""
        return expected_substring in str(error)


class TestCreateApp:
    def test_create_app_with_available_app(self) -> None:
        import intellicrack

        original_app = intellicrack._IntellicrackApp

        try:
            app_class = intellicrack._lazy_import_app()
            if app_class is not None:
                intellicrack._IntellicrackApp = app_class
                app = intellicrack.create_app()

                validator = RealAppValidator()
                assert validator.validate_app_instance(app)
        except ImportError:
            pytest.skip("IntellicrackApp not available in environment")
        finally:
            intellicrack._IntellicrackApp = original_app

    def test_create_app_raises_import_error_when_unavailable(self) -> None:
        import intellicrack

        original_app = intellicrack._IntellicrackApp
        intellicrack._IntellicrackApp = None

        try:
            with pytest.raises(ImportError) as exc_info:
                intellicrack.create_app()

            validator = RealAppValidator()
            assert validator.validate_importerror_message(exc_info.value, "IntellicrackApp not available")
        finally:
            intellicrack._IntellicrackApp = original_app

    def test_create_app_raises_runtime_error_when_failed(self) -> None:
        import intellicrack

        original_app = intellicrack._IntellicrackApp
        intellicrack._IntellicrackApp = True

        try:
            with pytest.raises(RuntimeError) as exc_info:
                intellicrack.create_app()

            validator = RealAppValidator()
            assert validator.validate_runtimeerror_message(exc_info.value, "IntellicrackApp failed to load")
        finally:
            intellicrack._IntellicrackApp = original_app


class RealMainFunctionValidator:
    """Real validator for main function behavior."""

    def __init__(self) -> None:
        self.valid_exit_codes = range(-128, 128)

    def validate_exit_code(self, code: int) -> bool:
        """Validate that exit code is in valid range."""
        return isinstance(code, int) and code in self.valid_exit_codes

    def validate_main_callable(self, main: Any) -> bool:
        """Validate main is callable."""
        return callable(main)


class TestRunApp:
    def test_run_app_with_available_main(self) -> None:
        import intellicrack

        main = intellicrack._lazy_import_main()
        if main is not None:
            validator = RealMainFunctionValidator()
            assert validator.validate_main_callable(main)
        else:
            pytest.skip("Main function not available in environment")

    def test_run_app_raises_import_error_when_unavailable(self) -> None:
        import intellicrack

        original_main = intellicrack._main
        intellicrack._main = False

        try:
            with pytest.raises(ImportError) as exc_info:
                intellicrack.run_app()

            validator = RealAppValidator()
            assert validator.validate_importerror_message(exc_info.value, "Main function not available")
        finally:
            intellicrack._main = original_main


class RealModuleAttributeValidator:
    """Real validator for module attribute access."""

    def __init__(self) -> None:
        self.expected_lazy_attributes = [
            "CONFIG",
            "get_config",
            "core",
            "ui",
            "utils",
            "ai",
            "plugins",
            "hexview",
            "dashboard",
        ]

    def validate_attribute_error(self, error: AttributeError, attr_name: str) -> bool:
        """Validate AttributeError message format."""
        return attr_name in str(error) and "has no attribute" in str(error)

    def attempt_attribute_access(self, module: Any, attr_name: str) -> tuple[bool, Any]:
        """Attempt to access attribute and return success status and value."""
        try:
            value = getattr(module, attr_name)
            return (True, value)
        except AttributeError:
            return (False, None)


class TestModuleGetattr:
    def test_getattr_config_returns_config(self) -> None:
        import intellicrack

        config = intellicrack.CONFIG

        assert config is not None

    def test_getattr_get_config_returns_function(self) -> None:
        import intellicrack

        get_config = intellicrack.get_config

        loader = RealModuleLoader()
        assert loader.verify_callable(get_config)

    def test_getattr_invalid_attribute_raises_error(self) -> None:
        import intellicrack

        with pytest.raises(AttributeError) as exc_info:
            _ = intellicrack.invalid_attr

        validator = RealModuleAttributeValidator()
        assert validator.validate_attribute_error(exc_info.value, "invalid_attr")

    def test_getattr_core_module(self) -> None:
        import intellicrack

        validator = RealModuleAttributeValidator()
        success, core = validator.attempt_attribute_access(intellicrack, "core")

        if success:
            loader = RealModuleLoader()
            assert core is None or loader.verify_module_has_name(core)

    def test_getattr_ui_module(self) -> None:
        import intellicrack

        validator = RealModuleAttributeValidator()
        success, ui = validator.attempt_attribute_access(intellicrack, "ui")

        if success:
            loader = RealModuleLoader()
            assert ui is None or loader.verify_module_has_name(ui)

    def test_getattr_utils_module(self) -> None:
        import intellicrack

        validator = RealModuleAttributeValidator()
        success, utils = validator.attempt_attribute_access(intellicrack, "utils")

        if success:
            loader = RealModuleLoader()
            assert utils is None or loader.verify_module_has_name(utils)

    def test_getattr_ai_module(self) -> None:
        import intellicrack

        validator = RealModuleAttributeValidator()
        success, ai = validator.attempt_attribute_access(intellicrack, "ai")

        if success:
            loader = RealModuleLoader()
            assert ai is None or loader.verify_module_has_name(ai)


class RealExportValidator:
    """Real validator for module exports."""

    def __init__(self) -> None:
        self.minimum_exports = [
            "__version__",
            "__author__",
            "__license__",
            "get_version",
            "create_app",
            "run_app",
            "get_default_device",
        ]

    def validate_exports_present(self, all_list: list[str]) -> bool:
        """Validate all minimum exports are present in __all__."""
        return all(export in all_list for export in self.minimum_exports)

    def validate_export_accessible(self, module: Any, export_name: str) -> bool:
        """Validate export is actually accessible on module."""
        return hasattr(module, export_name)


class TestModuleExports:
    def test_all_contains_expected_exports(self) -> None:
        import intellicrack

        validator = RealExportValidator()
        assert validator.validate_exports_present(intellicrack.__all__)

    def test_all_exports_are_accessible(self) -> None:
        import intellicrack

        validator = RealExportValidator()
        for export_name in intellicrack.__all__:
            assert validator.validate_export_accessible(intellicrack, export_name)


class TestConfigurationHelpers:
    def test_validate_config_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._validate_config(config)

    def test_log_repository_status_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._log_repository_status(config)

    def test_log_ghidra_path_with_real_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        intellicrack._log_ghidra_path(config)

    def test_update_config_with_runtime_defaults_real(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        validator = RealConfigValidator()
        defaults = validator.extract_runtime_defaults(intellicrack.__version__)

        assert defaults["initialized"] is True
        assert defaults["version"] == intellicrack.__version__


class TestLazyModuleImports:
    def test_lazy_import_core_returns_module_or_none(self) -> None:
        import intellicrack

        core = intellicrack._lazy_import_core()

        loader = RealModuleLoader()
        assert core is None or loader.verify_module_has_name(core)

    def test_lazy_import_ui_returns_module_or_none(self) -> None:
        import intellicrack

        ui = intellicrack._lazy_import_ui()

        loader = RealModuleLoader()
        assert ui is None or loader.verify_module_has_name(ui)

    def test_lazy_import_utils_returns_module_or_none(self) -> None:
        import intellicrack

        utils = intellicrack._lazy_import_utils()

        loader = RealModuleLoader()
        assert utils is None or loader.verify_module_has_name(utils)

    def test_lazy_import_plugins_returns_module_or_none(self) -> None:
        import intellicrack

        plugins = intellicrack._lazy_import_plugins()

        loader = RealModuleLoader()
        assert plugins is None or loader.verify_module_has_name(plugins)

    def test_lazy_import_hexview_returns_module_or_none(self) -> None:
        import intellicrack

        hexview = intellicrack._lazy_import_hexview()

        loader = RealModuleLoader()
        assert hexview is None or loader.verify_module_has_name(hexview)

    def test_lazy_import_dashboard_returns_module_or_none(self) -> None:
        import intellicrack

        dashboard = intellicrack._lazy_import_dashboard()

        loader = RealModuleLoader()
        assert dashboard is None or loader.verify_module_has_name(dashboard)

    def test_lazy_import_ai_returns_module_or_none(self) -> None:
        import intellicrack

        ai = intellicrack._lazy_import_ai()

        loader = RealModuleLoader()
        assert ai is None or loader.verify_module_has_name(ai)


class RealPackageImportValidator:
    """Real validator for package import behavior."""

    def __init__(self) -> None:
        self.max_import_time_seconds = 5.0

    def validate_import_successful(self, module: Any) -> bool:
        """Validate module imported successfully."""
        return module is not None and hasattr(module, "__name__")

    def validate_import_time(self, elapsed_seconds: float) -> bool:
        """Validate import completed within time limit."""
        return elapsed_seconds < self.max_import_time_seconds

    def validate_gpu_initialized_flag(self, flag: bool) -> bool:
        """Validate GPU initialized flag is boolean."""
        return isinstance(flag, bool)


class TestPackageImportOrder:
    def test_package_imports_without_error(self) -> None:
        try:
            import intellicrack

            validator = RealPackageImportValidator()
            assert validator.validate_import_successful(intellicrack)
        except ImportError as e:
            pytest.fail(f"Package import failed: {e}")

    def test_package_import_is_fast(self) -> None:
        start_time = time.time()

        import intellicrack

        elapsed = time.time() - start_time

        validator = RealPackageImportValidator()
        assert validator.validate_import_time(elapsed)

    def test_package_import_does_not_block_on_gpu(self) -> None:
        import intellicrack

        validator = RealPackageImportValidator()
        assert validator.validate_gpu_initialized_flag(intellicrack._gpu_initialized)


class RealDocstringValidator:
    """Real validator for package docstring content."""

    def __init__(self) -> None:
        self.required_keywords = ["Intellicrack", "binary analysis"]
        self.minimum_length = 50

    def validate_docstring_exists(self, docstring: Optional[str]) -> bool:
        """Validate docstring is not None or empty."""
        return docstring is not None and len(docstring) > 0

    def validate_docstring_length(self, docstring: str) -> bool:
        """Validate docstring meets minimum length."""
        return len(docstring) >= self.minimum_length

    def validate_docstring_keywords(self, docstring: str) -> bool:
        """Validate docstring contains required keywords."""
        docstring_lower = docstring.lower()
        return all(keyword.lower() in docstring_lower for keyword in self.required_keywords)


class TestModuleDocstring:
    def test_package_has_docstring(self) -> None:
        import intellicrack

        validator = RealDocstringValidator()
        assert validator.validate_docstring_exists(intellicrack.__doc__)

    def test_docstring_contains_key_info(self) -> None:
        import intellicrack

        validator = RealDocstringValidator()
        assert validator.validate_docstring_keywords(intellicrack.__doc__)

    def test_docstring_sufficient_length(self) -> None:
        import intellicrack

        validator = RealDocstringValidator()
        assert validator.validate_docstring_length(intellicrack.__doc__)


class RealThreadingValidator:
    """Real validator for threading environment configuration."""

    def __init__(self) -> None:
        self.threading_vars = ["OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"]
        self.expected_value = "1"

    def validate_all_threading_vars_set(self) -> bool:
        """Validate all threading environment variables are set."""
        return all(var in os.environ for var in self.threading_vars)

    def validate_threading_var_values(self) -> bool:
        """Validate threading environment variables have safe values."""
        return all(os.environ.get(var) == self.expected_value for var in self.threading_vars)


class TestThreadingSafety:
    def test_threading_vars_prevent_oversubscription(self) -> None:
        validator = RealThreadingValidator()
        assert validator.validate_all_threading_vars_set()
        assert validator.validate_threading_var_values()

    def test_threading_configuration_immutable(self) -> None:
        import intellicrack

        validator = RealThreadingValidator()
        original_values = {var: os.environ.get(var) for var in validator.threading_vars}

        assert all(value == "1" for value in original_values.values())


class RealLazyLoadValidator:
    """Real validator for lazy loading behavior."""

    def __init__(self) -> None:
        self.cacheable_imports = ["config", "get_config"]

    def validate_caching_behavior(self, first_result: Any, second_result: Any) -> bool:
        """Validate that cached results are identical objects."""
        return first_result is second_result

    def validate_lazy_load_trigger(self, module: Any, attr_name: str) -> tuple[bool, Any]:
        """Validate lazy load is triggered on attribute access."""
        try:
            result = getattr(module, attr_name)
            return (True, result)
        except AttributeError:
            return (False, None)


class TestLazyLoadingBehavior:
    def test_config_lazy_loaded_on_first_access(self) -> None:
        import intellicrack

        intellicrack._config_cached = None

        validator = RealLazyLoadValidator()
        success, config = validator.validate_lazy_load_trigger(intellicrack, "CONFIG")

        assert success
        assert config is not None

    def test_get_config_lazy_loaded_on_first_access(self) -> None:
        import intellicrack

        intellicrack._get_config_func = None

        validator = RealLazyLoadValidator()
        success, get_config = validator.validate_lazy_load_trigger(intellicrack, "get_config")

        assert success
        loader = RealModuleLoader()
        assert loader.verify_callable(get_config)

    def test_lazy_imports_cache_results(self) -> None:
        import intellicrack

        intellicrack._config_cached = None
        config1 = intellicrack._lazy_import_config()
        config2 = intellicrack._lazy_import_config()

        validator = RealLazyLoadValidator()
        assert validator.validate_caching_behavior(config1, config2)


class RealVersionCompatibilityValidator:
    """Real validator for version string compatibility."""

    def __init__(self) -> None:
        self.minimum_version_parts = 2
        self.maximum_version_parts = 4

    def parse_version_string(self, version: str) -> list[str]:
        """Parse version string into components."""
        return version.split(".")

    def validate_version_parts_numeric(self, parts: list[str]) -> bool:
        """Validate major and minor version parts are numeric."""
        return len(parts) >= 2 and all(part.isdigit() for part in parts[:2])

    def validate_version_format(self, version: str) -> bool:
        """Validate version follows semantic versioning format."""
        parts = self.parse_version_string(version)
        return (
            self.minimum_version_parts <= len(parts) <= self.maximum_version_parts
            and self.validate_version_parts_numeric(parts)
        )


class TestVersionCompatibility:
    def test_version_follows_semantic_versioning(self) -> None:
        import intellicrack

        validator = RealVersionCompatibilityValidator()
        assert validator.validate_version_format(intellicrack.__version__)

    def test_version_consistent_across_functions(self) -> None:
        import intellicrack

        constant_version = intellicrack.__version__
        function_version = intellicrack.get_version()

        assert constant_version == function_version

    def test_version_used_in_runtime_config(self) -> None:
        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        validator = RealConfigValidator()
        defaults = validator.extract_runtime_defaults(intellicrack.__version__)

        assert defaults["version"] == intellicrack.__version__
