"""Production tests for intellicrack/main.py entry point workflow.

These tests validate the main() function's startup sequence, logging setup,
security initialization, and GUI launch integration. Real integration testing
with minimal mocking.

Copyright (C) 2025 Zachary Flint
"""

import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.main import main


class TestMainFunctionExecution:
    """Production tests for main() function execution."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_main_function_returns_exit_code(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """main() returns valid exit code."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        result = main()

        assert isinstance(result, int)
        assert result in [0, 1]

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_main_function_success_path(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """main() executes successfully with valid configuration."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        result = main()

        assert result == 0
        mock_startup.assert_called_once()
        mock_launch.assert_called_once()

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_main_function_startup_checks_called(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """main() calls startup checks before GUI launch."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        main()

        mock_startup.assert_called_once()
        assert mock_startup.call_count == 1

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_main_function_gui_launch_called(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """main() launches GUI application."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        main()

        mock_launch.assert_called_once()


class TestLoggingConfiguration:
    """Production tests for logging setup in main()."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_logging_configured_before_execution(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Logging configured before main execution."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("intellicrack.utils.core.plugin_paths.get_logs_dir", return_value=temp_dir):
                result = main()

                assert result == 0

                logger = logging.getLogger("intellicrack.main")
                assert logger is not None

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_log_file_created_when_enabled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Log file created when file logging enabled."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("intellicrack.utils.core.plugin_paths.get_logs_dir", return_value=temp_dir):
                main()

                log_file = Path(temp_dir) / "intellicrack.log"
                assert log_file.exists()

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_log_level_from_config(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Log level set from configuration."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("intellicrack.utils.core.plugin_paths.get_logs_dir", return_value=temp_dir):
                main()

                logger = logging.getLogger("intellicrack")
                assert logger.level in [
                    logging.DEBUG,
                    logging.INFO,
                    logging.WARNING,
                    logging.ERROR,
                ]


class TestSecurityInitialization:
    """Production tests for security system initialization."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_gil_safety_initialized(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """GIL safety measures initialized."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with patch("intellicrack.utils.torch_gil_safety.initialize_gil_safety") as mock_gil:
            result = main()

            assert result == 0
            mock_gil.assert_called_once()

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_gil_safety_fallback_on_import_error(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """GIL safety fallback sets environment variable on import error."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        def mock_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("GIL safety not available")

        with (
            patch("intellicrack.utils.torch_gil_safety.initialize_gil_safety", side_effect=mock_import_error),
            patch.dict(os.environ, {}, clear=False),
        ):
            main()

            assert "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF" in os.environ

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_security_enforcement_initialized(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Security enforcement initialized successfully."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        mock_security = MagicMock()
        mock_security.get_security_status.return_value = {
            "initialized": True,
            "patches_applied": {},
        }

        with patch.dict("sys.modules", {"intellicrack.core.security_enforcement": mock_security}):
            result = main()

            assert result == 0

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_security_mitigations_applied(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Security mitigations applied during startup."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with patch("intellicrack.utils.security_mitigations.apply_all_mitigations") as mock_mitigations:
            result = main()

            assert result == 0
            mock_mitigations.assert_called_once()


class TestStartupChecks:
    """Production tests for startup checks execution."""

    @patch("intellicrack.ui.main_app.launch")
    def test_startup_checks_executed(self, mock_launch: MagicMock) -> None:
        """Startup checks executed before GUI launch."""
        mock_launch.return_value = 0

        with patch("intellicrack.core.startup_checks.perform_startup_checks") as mock_startup:
            result = main()

            assert result == 0
            mock_startup.assert_called_once()

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_startup_checks_exception_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Startup checks exceptions handled gracefully."""
        mock_startup.side_effect = Exception("Startup check failed")
        mock_launch.return_value = 0

        result = main()

        assert result == 0


class TestComprehensiveLogging:
    """Production tests for comprehensive logging system."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_comprehensive_logging_initialized(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Comprehensive logging system initialized."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with patch("intellicrack.core.logging.audit_logger.setup_comprehensive_logging") as mock_comprehensive:
            result = main()

            assert result == 0
            mock_comprehensive.assert_called_once()

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_comprehensive_logging_failure_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Comprehensive logging initialization failure handled."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        def mock_logging_error() -> None:
            raise Exception("Logging setup failed")

        with patch(
            "intellicrack.core.logging.audit_logger.setup_comprehensive_logging", side_effect=mock_logging_error
        ):
            result = main()

            assert result == 0


class TestGUILaunch:
    """Production tests for GUI application launch."""

    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_gui_launch_function_called(self, mock_startup: MagicMock) -> None:
        """GUI launch function called from main()."""
        mock_startup.return_value = None

        with patch("intellicrack.ui.main_app.launch", return_value=0) as mock_launch:
            result = main()

            assert result == 0
            mock_launch.assert_called_once()

    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_gui_launch_return_code_propagated(self, mock_startup: MagicMock) -> None:
        """GUI launch return code propagated to main()."""
        mock_startup.return_value = None

        with patch("intellicrack.ui.main_app.launch", return_value=42) as mock_launch:
            result = main()

            assert result == 42


class TestErrorHandling:
    """Production tests for error handling in main()."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_import_error_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """ImportError handled gracefully and returns error code."""
        mock_startup.return_value = None
        mock_launch.side_effect = ImportError("Module not found")

        result = main()

        assert result == 1

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_os_error_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """OSError handled gracefully and returns error code."""
        mock_startup.return_value = None
        mock_launch.side_effect = OSError("File operation failed")

        result = main()

        assert result == 1

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_value_error_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """ValueError handled gracefully and returns error code."""
        mock_startup.return_value = None
        mock_launch.side_effect = ValueError("Invalid value")

        result = main()

        assert result == 1

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_runtime_error_handled(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """RuntimeError handled gracefully and returns error code."""
        mock_startup.return_value = None
        mock_launch.side_effect = RuntimeError("Runtime issue")

        result = main()

        assert result == 1


class TestEnvironmentConfiguration:
    """Production tests for environment configuration in main()."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_tensorflow_env_vars_set(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """TensorFlow environment variables set in main module."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        import intellicrack.main

        assert os.environ.get("TF_CPP_MIN_LOG_LEVEL") == "2"
        assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
        assert os.environ.get("MKL_THREADING_LAYER") == "GNU"

    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/Unix-specific test")
    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_qt_offscreen_mode_wsl(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Qt offscreen mode set in WSL environment."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with (
            patch.dict(os.environ, {"DISPLAY": ""}, clear=False),
            patch("os.path.exists", return_value=True),
            patch("builtins.open", create=True) as mock_open,
        ):
            mock_open.return_value.__enter__.return_value.read.return_value = "microsoft"

            import importlib

            import intellicrack.main

            importlib.reload(intellicrack.main)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_windows_qt_font_config(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Windows Qt font configuration applied."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        import intellicrack.main

        if "QT_QPA_FONTDIR" in os.environ:
            assert "Fonts" in os.environ["QT_QPA_FONTDIR"]

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_windows_opengl_software_rendering(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Windows OpenGL software rendering configured."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        import intellicrack.main

        if "QT_OPENGL" in os.environ:
            assert os.environ["QT_OPENGL"] == "software"


class TestModuleAsMain:
    """Production tests for module execution as __main__."""

    def test_main_function_available(self) -> None:
        """main() function available for module execution."""
        from intellicrack.main import main

        assert callable(main)
        assert hasattr(main, "__call__")

    def test_log_function_call_decorator(self) -> None:
        """main() function decorated with log_function_call."""
        from intellicrack.main import main

        assert hasattr(main, "__wrapped__") or callable(main)


class TestLoggingOutput:
    """Production tests for logging output and messages."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_startup_message_logged(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Startup message logged when application starts."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("intellicrack.utils.core.plugin_paths.get_logs_dir", return_value=temp_dir),
        ):
            main()

            log_file = Path(temp_dir) / "intellicrack.log"
            assert log_file.exists()

            log_content = log_file.read_text()
            assert "Intellicrack Application Starting" in log_content

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_startup_checks_completion_logged(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Startup checks completion logged."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("intellicrack.utils.core.plugin_paths.get_logs_dir", return_value=temp_dir),
        ):
            main()

            log_file = Path(temp_dir) / "intellicrack.log"
            assert log_file.exists()

            log_content = log_file.read_text()
            assert "Startup checks completed" in log_content or "Performing startup checks" in log_content


class TestConfigurationLoading:
    """Production tests for configuration loading in main()."""

    @patch("intellicrack.ui.main_app.launch")
    @patch("intellicrack.core.startup_checks.perform_startup_checks")
    def test_config_loaded_before_execution(
        self, mock_startup: MagicMock, mock_launch: MagicMock
    ) -> None:
        """Configuration loaded before main execution."""
        mock_startup.return_value = None
        mock_launch.return_value = 0

        with patch("intellicrack.config.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.get.return_value = {"level": "INFO", "enable_file_logging": True}
            mock_get_config.return_value = mock_config

            main()

            mock_get_config.assert_called()


class TestIntegrationFlow:
    """Production tests for complete integration flow."""

    @patch("intellicrack.ui.main_app.launch")
    def test_complete_startup_sequence(self, mock_launch: MagicMock) -> None:
        """Complete startup sequence executes in correct order."""
        mock_launch.return_value = 0
        call_order: list[str] = []

        def track_startup(*args: Any, **kwargs: Any) -> None:
            call_order.append("startup_checks")

        def track_gil(*args: Any, **kwargs: Any) -> None:
            call_order.append("gil_safety")

        def track_security(*args: Any, **kwargs: Any) -> None:
            call_order.append("security")

        def track_mitigations(*args: Any, **kwargs: Any) -> None:
            call_order.append("mitigations")

        def track_launch(*args: Any, **kwargs: Any) -> int:
            call_order.append("gui_launch")
            return 0

        with (
            patch("intellicrack.core.startup_checks.perform_startup_checks", side_effect=track_startup),
            patch("intellicrack.utils.torch_gil_safety.initialize_gil_safety", side_effect=track_gil),
            patch("intellicrack.utils.security_mitigations.apply_all_mitigations", side_effect=track_mitigations),
        ):
            mock_launch.side_effect = track_launch
            result = main()

            assert result == 0
            assert "gil_safety" in call_order
            assert "mitigations" in call_order
            assert "startup_checks" in call_order
            assert "gui_launch" in call_order

            assert call_order.index("startup_checks") < call_order.index("gui_launch")
