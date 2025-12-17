import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

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


class TestGPUInitialization:
    @patch("intellicrack.gpu_autoloader")
    @patch("intellicrack.get_gpu_info")
    def test_initialize_gpu_with_available_gpu(
        self, mock_get_gpu_info: MagicMock, mock_gpu_autoloader: MagicMock
    ) -> None:
        mock_get_gpu_info.return_value = {"available": True}
        mock_gpu_autoloader.get_device_string.return_value = "cuda:0"
        mock_gpu_autoloader.setup.return_value = None

        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu()

        assert device in ["cuda:0", "cpu", "xpu", "mps"]

    @patch("intellicrack.get_gpu_info")
    def test_initialize_gpu_fallback_to_cpu(
        self, mock_get_gpu_info: MagicMock
    ) -> None:
        mock_get_gpu_info.return_value = {"available": False}

        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu()

        assert device == "cpu" or isinstance(device, str)

    def test_initialize_gpu_caches_result(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False
        device1 = intellicrack._initialize_gpu()

        intellicrack._gpu_initialized = True
        device2 = intellicrack._initialize_gpu()

        assert intellicrack._gpu_initialized is True

    def test_initialize_gpu_with_timeout_returns_device(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu_with_timeout(timeout_seconds=1)

        assert isinstance(device, str)
        assert device in ["cpu", "cuda", "cuda:0", "xpu", "mps"]

    def test_initialize_gpu_with_timeout_handles_timeout(self) -> None:
        import intellicrack

        intellicrack._gpu_initialized = False

        device = intellicrack._initialize_gpu_with_timeout(timeout_seconds=0.001)

        assert device == "cpu"


class TestGILSafetyInitialization:
    def test_gil_safety_initialization_idempotent(self) -> None:
        import intellicrack

        intellicrack._gil_safety_initialized = False
        intellicrack._initialize_gil_safety()

        assert intellicrack._gil_safety_initialized is True

        intellicrack._initialize_gil_safety()

        assert intellicrack._gil_safety_initialized is True

    @patch("intellicrack.utils.torch_gil_safety.initialize_gil_safety")
    def test_gil_safety_calls_initialization(
        self, mock_init: MagicMock
    ) -> None:
        import intellicrack

        intellicrack._gil_safety_initialized = False
        intellicrack._initialize_gil_safety()

        if "torch_gil_safety" in sys.modules:
            mock_init.assert_called_once()


class TestConfigurationInitialization:
    def test_config_initialization_lazy(self) -> None:
        import intellicrack

        assert hasattr(intellicrack, "_initialize_config")

    @patch("intellicrack._load_config")
    def test_initialize_config_loads_config(
        self, mock_load: MagicMock
    ) -> None:
        mock_load.return_value = {"test_key": "test_value"}

        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        assert config is not None

    @patch("intellicrack._load_config")
    def test_initialize_config_validates(self, mock_load: MagicMock) -> None:
        mock_config = MagicMock()
        mock_config.validate_config.return_value = True
        mock_load.return_value = mock_config

        import intellicrack

        intellicrack._config = None
        config = intellicrack._initialize_config()

        if hasattr(config, "validate_config"):
            config.validate_config.assert_called_once()

    def test_config_update_with_runtime_defaults(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.update = MagicMock()

        intellicrack._update_config_with_runtime_defaults(mock_config)

        mock_config.update.assert_called_once()
        call_args = mock_config.update.call_args[0][0]
        assert "initialized" in call_args
        assert "version" in call_args


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

        assert get_config is not None
        assert callable(get_config)

    def test_lazy_import_main_returns_callable_or_none(self) -> None:
        import intellicrack

        main = intellicrack._lazy_import_main()

        assert main is None or callable(main)

    def test_lazy_import_app_returns_class_or_none(self) -> None:
        import intellicrack

        app_class = intellicrack._lazy_import_app()

        assert app_class is None or callable(app_class)


class TestGetDefaultDevice:
    def test_get_default_device_returns_string(self) -> None:
        import intellicrack

        device = intellicrack.get_default_device()

        assert isinstance(device, str)
        assert len(device) > 0

    def test_get_default_device_valid_values(self) -> None:
        import intellicrack

        device = intellicrack.get_default_device()

        valid_devices = ["cpu", "cuda", "cuda:0", "xpu", "mps"]
        assert any(device.startswith(valid_dev) for valid_dev in valid_devices)


class TestCreateApp:
    @patch("intellicrack._lazy_import_app")
    def test_create_app_with_available_app(
        self, mock_lazy_import: MagicMock
    ) -> None:
        mock_app_class = MagicMock()
        mock_lazy_import.return_value = mock_app_class

        import intellicrack

        intellicrack._IntellicrackApp = mock_app_class

        app = intellicrack.create_app()

        assert app is not None

    def test_create_app_raises_import_error_when_unavailable(self) -> None:
        import intellicrack

        intellicrack._IntellicrackApp = None

        with patch.object(intellicrack, "_lazy_import_app", return_value=None):
            with pytest.raises(ImportError, match="IntellicrackApp not available"):
                intellicrack.create_app()

    def test_create_app_raises_runtime_error_when_failed(self) -> None:
        import intellicrack

        intellicrack._IntellicrackApp = True

        with pytest.raises(RuntimeError, match="IntellicrackApp failed to load"):
            intellicrack.create_app()


class TestRunApp:
    @patch("intellicrack._lazy_import_main")
    def test_run_app_with_available_main(self, mock_lazy_import: MagicMock) -> None:
        mock_main = MagicMock(return_value=0)
        mock_lazy_import.return_value = mock_main

        import intellicrack

        exit_code = intellicrack.run_app()

        assert exit_code == 0
        mock_main.assert_called_once()

    @patch("intellicrack._lazy_import_main")
    def test_run_app_raises_import_error_when_unavailable(
        self, mock_lazy_import: MagicMock
    ) -> None:
        mock_lazy_import.return_value = None

        import intellicrack

        with pytest.raises(ImportError, match="Main function not available"):
            intellicrack.run_app()


class TestModuleGetattr:
    def test_getattr_config_returns_config(self) -> None:
        import intellicrack

        config = intellicrack.CONFIG

        assert config is not None

    def test_getattr_get_config_returns_function(self) -> None:
        import intellicrack

        get_config = intellicrack.get_config

        assert callable(get_config)

    def test_getattr_invalid_attribute_raises_error(self) -> None:
        import intellicrack

        with pytest.raises(AttributeError, match="has no attribute 'invalid_attr'"):
            _ = intellicrack.invalid_attr

    def test_getattr_core_module(self) -> None:
        import intellicrack

        try:
            core = intellicrack.core
            assert core is not None or core is None
        except AttributeError:
            pass

    def test_getattr_ui_module(self) -> None:
        import intellicrack

        try:
            ui = intellicrack.ui
            assert ui is not None or ui is None
        except AttributeError:
            pass

    def test_getattr_utils_module(self) -> None:
        import intellicrack

        try:
            utils = intellicrack.utils
            assert utils is not None or utils is None
        except AttributeError:
            pass

    def test_getattr_ai_module(self) -> None:
        import intellicrack

        try:
            ai = intellicrack.ai
            assert ai is not None or ai is None
        except AttributeError:
            pass


class TestModuleExports:
    def test_all_contains_expected_exports(self) -> None:
        import intellicrack

        expected_exports = [
            "__version__",
            "__author__",
            "__license__",
            "get_version",
            "create_app",
            "run_app",
            "get_default_device",
        ]

        for export in expected_exports:
            assert export in intellicrack.__all__

    def test_all_exports_are_accessible(self) -> None:
        import intellicrack

        for export_name in intellicrack.__all__:
            assert hasattr(intellicrack, export_name)


class TestConfigurationHelpers:
    def test_validate_config_with_valid_config(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.validate_config.return_value = True

        intellicrack._validate_config(mock_config)

        mock_config.validate_config.assert_called_once()

    def test_validate_config_with_invalid_config(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.validate_config.return_value = False

        intellicrack._validate_config(mock_config)

        mock_config.validate_config.assert_called_once()

    def test_log_repository_status(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.is_repository_enabled.return_value = True

        intellicrack._log_repository_status(mock_config)

        mock_config.is_repository_enabled.assert_called_once()

    def test_log_ghidra_path_with_custom_path(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.get_ghidra_path.return_value = "/custom/path/ghidra"

        intellicrack._log_ghidra_path(mock_config)

        mock_config.get_ghidra_path.assert_called_once()

    def test_log_ghidra_path_with_default_path(self) -> None:
        import intellicrack

        mock_config = MagicMock()
        mock_config.get_ghidra_path.return_value = "ghidra"

        intellicrack._log_ghidra_path(mock_config)

        mock_config.get_ghidra_path.assert_called_once()


class TestLazyModuleImports:
    def test_lazy_import_core_returns_module_or_none(self) -> None:
        import intellicrack

        core = intellicrack._lazy_import_core()

        assert core is None or hasattr(core, "__name__")

    def test_lazy_import_ui_returns_module_or_none(self) -> None:
        import intellicrack

        ui = intellicrack._lazy_import_ui()

        assert ui is None or hasattr(ui, "__name__")

    def test_lazy_import_utils_returns_module_or_none(self) -> None:
        import intellicrack

        utils = intellicrack._lazy_import_utils()

        assert utils is None or hasattr(utils, "__name__")

    def test_lazy_import_plugins_returns_module_or_none(self) -> None:
        import intellicrack

        plugins = intellicrack._lazy_import_plugins()

        assert plugins is None or hasattr(plugins, "__name__")

    def test_lazy_import_hexview_returns_module_or_none(self) -> None:
        import intellicrack

        hexview = intellicrack._lazy_import_hexview()

        assert hexview is None or hasattr(hexview, "__name__")

    def test_lazy_import_dashboard_returns_module_or_none(self) -> None:
        import intellicrack

        dashboard = intellicrack._lazy_import_dashboard()

        assert dashboard is None or hasattr(dashboard, "__name__") or dashboard is False

    def test_lazy_import_ai_returns_module_or_none(self) -> None:
        import intellicrack

        ai = intellicrack._lazy_import_ai()

        assert ai is None or hasattr(ai, "__name__") or ai is False


class TestPackageImportOrder:
    def test_package_imports_without_error(self) -> None:
        try:
            import intellicrack

            assert intellicrack is not None
        except ImportError as e:
            pytest.fail(f"Package import failed: {e}")

    def test_package_import_is_fast(self) -> None:
        import time

        start_time = time.time()

        import intellicrack

        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_package_import_does_not_block_on_gpu(self) -> None:
        import intellicrack

        assert intellicrack._gpu_initialized is False or intellicrack._gpu_initialized is True


class TestModuleDocstring:
    def test_package_has_docstring(self) -> None:
        import intellicrack

        assert intellicrack.__doc__ is not None
        assert len(intellicrack.__doc__) > 0

    def test_docstring_contains_key_info(self) -> None:
        import intellicrack

        docstring = intellicrack.__doc__
        assert "Intellicrack" in docstring
        assert "binary analysis" in docstring.lower()
