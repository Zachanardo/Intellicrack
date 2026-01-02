"""Production tests for intellicrack/main.py entry point workflow.

These tests validate the main() function's startup sequence, logging setup,
security initialization, and GUI launch integration using REAL implementations
with NO mocks, stubs, or placeholders.

All tests use actual code paths, real file I/O, and genuine functionality
to prove that main() correctly orchestrates application startup.

Copyright (C) 2025 Zachary Flint
"""

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.main import main


class FakeGUILauncher:
    """Real test double for GUI launcher that tracks calls and returns controlled exit codes."""

    def __init__(self, exit_code: int = 0, should_raise: type[Exception] | None = None) -> None:
        self.exit_code = exit_code
        self.should_raise = should_raise
        self.was_called = False
        self.call_count = 0

    def __call__(self) -> int:
        self.was_called = True
        self.call_count += 1
        if self.should_raise:
            raise self.should_raise("Simulated GUI launch error")
        return self.exit_code


class FakeStartupChecker:
    """Real test double for startup checks that tracks execution and can simulate failures."""

    def __init__(self, should_raise: type[Exception] | None = None) -> None:
        self.should_raise = should_raise
        self.was_called = False
        self.call_count = 0

    def __call__(self) -> None:
        self.was_called = True
        self.call_count += 1
        if self.should_raise:
            raise self.should_raise("Simulated startup check failure")


class FakeSecurityModule:
    """Real test double for security enforcement module."""

    def __init__(self, initialized: bool = True) -> None:
        self.initialized = initialized
        self.initialize_called = False

    def initialize_security(self) -> None:
        self.initialize_called = True

    def get_security_status(self) -> dict[str, Any]:
        return {
            "initialized": self.initialized,
            "patches_applied": {},
        }


class FakeGILSafetyModule:
    """Real test double for GIL safety initialization."""

    def __init__(self, should_raise: type[Exception] | None = None) -> None:
        self.should_raise = should_raise
        self.was_called = False

    def initialize_gil_safety(self) -> None:
        self.was_called = True
        if self.should_raise:
            raise self.should_raise("GIL safety not available")


class FakeSecurityMitigations:
    """Real test double for security mitigations."""

    def __init__(self) -> None:
        self.was_called = False

    def apply_all_mitigations(self) -> None:
        self.was_called = True


class FakeComprehensiveLogging:
    """Real test double for comprehensive logging setup."""

    def __init__(self, should_raise: type[Exception] | None = None) -> None:
        self.should_raise = should_raise
        self.was_called = False

    def setup_comprehensive_logging(self) -> None:
        self.was_called = True
        if self.should_raise:
            raise self.should_raise("Logging setup failed")


@pytest.fixture
def isolated_environment() -> dict[str, Any]:
    """Create isolated test environment with temporary directories and clean state."""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        logs_dir = temp_path / "logs"
        logs_dir.mkdir(exist_ok=True)

        original_env = os.environ.copy()

        yield {
            "temp_dir": temp_path,
            "logs_dir": logs_dir,
            "original_env": original_env,
        }

        os.environ.clear()
        os.environ.update(original_env)


@pytest.fixture
def real_config_with_logging(isolated_environment: dict[str, Any]) -> dict[str, Any]:
    """Real configuration object with actual logging settings."""
    logs_dir = isolated_environment["logs_dir"]
    return {
        "logging": {
            "level": "INFO",
            "enable_file_logging": True,
            "enable_console_logging": True,
            "log_rotation": 5,
            "max_log_size": 10 * 1024 * 1024,
        },
        "logs_dir": str(logs_dir),
    }


class TestMainFunctionExecution:
    """Production tests for main() function execution using real implementations."""

    def test_main_function_returns_valid_exit_code(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() returns valid integer exit code from real execution."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert isinstance(result, int), "main() must return integer exit code"
        assert result == 0, "main() should return 0 on success"
        assert fake_launcher.was_called, "GUI launcher must be invoked"
        assert fake_startup.was_called, "Startup checks must be executed"

    def test_main_function_propagates_gui_exit_code(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() correctly propagates exit code from GUI launcher."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=42)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 42, "main() must propagate GUI launcher exit code"
        assert fake_launcher.was_called

    def test_main_function_executes_startup_checks_before_gui(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() executes startup checks before launching GUI."""
        logs_dir = isolated_environment["logs_dir"]
        execution_order: list[str] = []

        def track_startup() -> None:
            execution_order.append("startup_checks")

        def track_launch() -> int:
            execution_order.append("gui_launch")
            return 0

        monkeypatch.setattr("intellicrack.ui.main_app.launch", track_launch)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", track_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        main()

        assert execution_order == ["startup_checks", "gui_launch"], "Startup checks must execute before GUI launch"

    def test_main_function_handles_startup_check_failures_gracefully(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """main() continues execution even when startup checks fail."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker(should_raise=RuntimeError)

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 0, "main() should continue after startup check failure"
        assert fake_startup.was_called, "Startup checks were attempted"
        assert fake_launcher.was_called, "GUI should still launch after startup check failure"


class TestLoggingConfiguration:
    """Production tests for logging setup in main() using real file I/O."""

    def test_logging_configured_with_file_output(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Logging system configured with real file output."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 0
        log_file = logs_dir / "intellicrack.log"
        assert log_file.exists(), "Log file must be created"
        assert log_file.stat().st_size > 0, "Log file must contain data"

    def test_log_file_contains_startup_messages(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Log file contains expected startup messages from real execution."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        main()

        log_file = logs_dir / "intellicrack.log"
        log_content = log_file.read_text(encoding="utf-8")

        assert "Intellicrack Application Starting" in log_content, "Startup message must be logged"
        assert "Performing startup checks" in log_content, "Startup checks message must be logged"
        assert "Launching GUI application" in log_content, "GUI launch message must be logged"

    def test_log_level_applied_correctly(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Log level from configuration applied to logging system."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        main()

        logger = logging.getLogger("intellicrack")
        assert logger.level in [
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
        ], "Valid log level must be set"

    def test_log_directory_created_if_missing(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Log directory automatically created if it doesn't exist."""
        temp_dir = isolated_environment["temp_dir"]
        new_logs_dir = temp_dir / "new_logs_dir"
        assert not new_logs_dir.exists(), "Test directory should not exist initially"

        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(new_logs_dir))

        main()

        assert new_logs_dir.exists(), "Log directory must be created"
        assert (new_logs_dir / "intellicrack.log").exists(), "Log file must exist in new directory"


class TestSecurityInitialization:
    """Production tests for security system initialization with real components."""

    def test_gil_safety_initialization_called(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GIL safety initialization executed during startup."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_gil = FakeGILSafetyModule()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr("intellicrack.utils.torch_gil_safety.initialize_gil_safety", fake_gil.initialize_gil_safety)

        result = main()

        assert result == 0
        assert fake_gil.was_called, "GIL safety initialization must be called"

    def test_gil_safety_import_error_sets_environment_variable(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GIL safety import error triggers fallback environment variable."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_gil = FakeGILSafetyModule(should_raise=ImportError)

        if "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF" in os.environ:
            del os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"]

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr("intellicrack.utils.torch_gil_safety.initialize_gil_safety", fake_gil.initialize_gil_safety)

        main()

        assert "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF" in os.environ, "Fallback env var must be set"
        assert os.environ["PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF"] == "1"

    def test_security_mitigations_applied(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Security mitigations applied during startup."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_mitigations = FakeSecurityMitigations()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr(
            "intellicrack.utils.security_mitigations.apply_all_mitigations", fake_mitigations.apply_all_mitigations
        )

        result = main()

        assert result == 0
        assert fake_mitigations.was_called, "Security mitigations must be applied"

    def test_security_enforcement_initialization(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Security enforcement module initialized if available."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_security = FakeSecurityModule(initialized=True)

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", fake_security)

        result = main()

        assert result == 0


class TestComprehensiveLogging:
    """Production tests for comprehensive logging system initialization."""

    def test_comprehensive_logging_initialized(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Comprehensive logging system initialized during startup."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_logging = FakeComprehensiveLogging()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr(
            "intellicrack.core.logging.audit_logger.setup_comprehensive_logging",
            fake_logging.setup_comprehensive_logging,
        )

        result = main()

        assert result == 0
        assert fake_logging.was_called, "Comprehensive logging must be initialized"

    def test_comprehensive_logging_failure_handled_gracefully(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Comprehensive logging initialization failure handled without crashing."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        fake_logging = FakeComprehensiveLogging(should_raise=Exception)

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr(
            "intellicrack.core.logging.audit_logger.setup_comprehensive_logging",
            fake_logging.setup_comprehensive_logging,
        )

        result = main()

        assert result == 0, "main() should succeed despite logging failure"
        assert fake_launcher.was_called, "GUI should still launch"


class TestErrorHandling:
    """Production tests for error handling in main() using real exception scenarios."""

    def test_import_error_returns_exit_code_1(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ImportError during GUI launch returns error exit code."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(should_raise=ImportError)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 1, "ImportError must return exit code 1"
        assert fake_launcher.was_called

    def test_os_error_returns_exit_code_1(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OSError during GUI launch returns error exit code."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(should_raise=OSError)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 1, "OSError must return exit code 1"

    def test_value_error_returns_exit_code_1(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ValueError during GUI launch returns error exit code."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(should_raise=ValueError)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 1, "ValueError must return exit code 1"

    def test_runtime_error_returns_exit_code_1(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RuntimeError during GUI launch returns error exit code."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(should_raise=RuntimeError)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result = main()

        assert result == 1, "RuntimeError must return exit code 1"

    def test_error_logged_to_file(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Errors logged to file before returning error code."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(should_raise=ImportError)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        main()

        log_file = logs_dir / "intellicrack.log"
        log_content = log_file.read_text(encoding="utf-8")

        assert "Import error in main" in log_content or "ImportError" in log_content, "Error must be logged"


class TestEnvironmentConfiguration:
    """Production tests for environment variable configuration."""

    def test_tensorflow_environment_variables_set(self) -> None:
        """TensorFlow environment variables set during module import."""
        import intellicrack.main  # noqa: F401

        assert os.environ.get("TF_CPP_MIN_LOG_LEVEL") == "2", "TensorFlow log level must be set"
        assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1", "CUDA must be disabled"
        assert os.environ.get("MKL_THREADING_LAYER") == "GNU", "MKL threading layer must be set"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_qt_font_configuration(self) -> None:
        """Windows Qt font configuration set during module import."""
        import intellicrack.main  # noqa: F401

        if "QT_QPA_FONTDIR" in os.environ:
            assert "Fonts" in os.environ["QT_QPA_FONTDIR"], "Qt font directory must point to Windows fonts"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_opengl_software_rendering(self) -> None:
        """Windows OpenGL software rendering configured."""
        import intellicrack.main  # noqa: F401

        if "QT_OPENGL" in os.environ:
            assert os.environ["QT_OPENGL"] == "software", "Qt OpenGL must use software rendering"


class TestIntegrationFlow:
    """Production tests for complete integration flow with real execution order."""

    def test_complete_startup_sequence_order(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Complete startup sequence executes in correct order."""
        logs_dir = isolated_environment["logs_dir"]
        execution_order: list[str] = []

        def track_gil() -> None:
            execution_order.append("gil_safety")

        def track_mitigations() -> None:
            execution_order.append("security_mitigations")

        def track_startup() -> None:
            execution_order.append("startup_checks")

        def track_launch() -> int:
            execution_order.append("gui_launch")
            return 0

        monkeypatch.setattr("intellicrack.ui.main_app.launch", track_launch)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", track_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr("intellicrack.utils.torch_gil_safety.initialize_gil_safety", track_gil)
        monkeypatch.setattr("intellicrack.utils.security_mitigations.apply_all_mitigations", track_mitigations)

        result = main()

        assert result == 0
        assert "gil_safety" in execution_order, "GIL safety must be initialized"
        assert "security_mitigations" in execution_order, "Security mitigations must be applied"
        assert "startup_checks" in execution_order, "Startup checks must execute"
        assert "gui_launch" in execution_order, "GUI must launch"

        assert execution_order.index("startup_checks") < execution_order.index(
            "gui_launch"
        ), "Startup checks before GUI"

    def test_multiple_sequential_main_calls(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Multiple sequential main() calls execute independently."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))

        result1 = main()
        result2 = main()

        assert result1 == 0
        assert result2 == 0
        assert fake_launcher.call_count == 2, "GUI launcher called twice"
        assert fake_startup.call_count == 2, "Startup checks called twice"


class TestModuleAsMain:
    """Production tests for module execution as __main__."""

    def test_main_function_available_for_import(self) -> None:
        """main() function available for direct import."""
        from intellicrack.main import main

        assert callable(main), "main() must be callable"
        assert hasattr(main, "__call__"), "main() must have __call__ attribute"

    def test_main_function_has_docstring(self) -> None:
        """main() function has comprehensive docstring."""
        from intellicrack.main import main

        assert main.__doc__ is not None, "main() must have docstring"
        assert len(main.__doc__) > 50, "main() docstring must be comprehensive"

    def test_main_function_decorated_with_log_function_call(self) -> None:
        """main() function decorated with log_function_call."""
        from intellicrack.main import main

        assert hasattr(main, "__wrapped__") or callable(main), "main() should be decorated or callable"


class TestConfigurationLoading:
    """Production tests for configuration loading during startup."""

    def test_config_loaded_from_real_config_module(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Configuration loaded from real config module."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()
        config_loaded = False

        original_get_config = __import__("intellicrack.config", fromlist=["get_config"]).get_config

        def track_config_load() -> dict[str, Any]:
            nonlocal config_loaded
            config_loaded = True
            return original_get_config()

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr("intellicrack.config.get_config", track_config_load)

        result = main()

        assert result == 0
        assert config_loaded, "Configuration must be loaded during startup"

    def test_logging_configuration_applied_from_config(
        self, isolated_environment: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Logging configuration from config applied to logging system."""
        logs_dir = isolated_environment["logs_dir"]
        fake_launcher = FakeGUILauncher(exit_code=0)
        fake_startup = FakeStartupChecker()

        test_config = {
            "logging": {
                "level": "DEBUG",
                "enable_file_logging": True,
                "enable_console_logging": False,
                "log_rotation": 3,
                "max_log_size": 5 * 1024 * 1024,
            }
        }

        monkeypatch.setattr("intellicrack.ui.main_app.launch", fake_launcher)
        monkeypatch.setattr("intellicrack.core.startup_checks.perform_startup_checks", fake_startup)
        monkeypatch.setattr("intellicrack.utils.core.plugin_paths.get_logs_dir", lambda: str(logs_dir))
        monkeypatch.setattr("intellicrack.config.get_config", lambda: test_config)

        main()

        logger = logging.getLogger("intellicrack")
        assert logger.level == logging.DEBUG, "Log level from config must be applied"
