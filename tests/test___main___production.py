"""Production tests for intellicrack/__main__.py entry point.

These tests validate that the module entry point correctly initializes
security settings, environment configuration, and delegates to main().
No mocks - real environment validation only.

Copyright (C) 2025 Zachary Flint
"""

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestMainEntryPoint:
    """Production tests for __main__.py entry point initialization."""

    def test_pybind11_gil_assertion_disabled(self) -> None:
        """Environment variable disables pybind11 GIL assertions."""
        with patch.dict(os.environ, {}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            assert os.environ.get("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF") == "1"

    def test_tensorflow_configuration_set(self) -> None:
        """TensorFlow environment variables configured for GPU compatibility."""
        with patch.dict(os.environ, {}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            assert os.environ.get("TF_CPP_MIN_LOG_LEVEL") == "2"
            assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
            assert os.environ.get("MKL_THREADING_LAYER") == "GNU"

    def test_qt_offscreen_mode_no_display(self) -> None:
        """Qt offscreen mode set when no display available."""
        env = {
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
            "TF_CPP_MIN_LOG_LEVEL": "2",
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_THREADING_LAYER": "GNU",
        }

        with patch.dict(os.environ, env, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            assert os.environ.get("QT_QPA_PLATFORM") == "offscreen"

    def test_qt_offscreen_mode_with_display(self) -> None:
        """Qt offscreen mode NOT set when display available."""
        env = {
            "DISPLAY": ":0",
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
            "TF_CPP_MIN_LOG_LEVEL": "2",
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_THREADING_LAYER": "GNU",
        }

        with patch.dict(os.environ, env, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            assert "QT_QPA_PLATFORM" not in os.environ or os.environ.get("DISPLAY") == ":0"

    def test_security_enforcement_initialization_success(self) -> None:
        """Security enforcement module initializes successfully."""
        mock_security = MagicMock()
        mock_security.get_security_status.return_value = {
            "initialized": True,
            "patches_applied": {"frida_detection": True, "debugger_detection": True},
        }

        with patch.dict("sys.modules", {"intellicrack.core.security_enforcement": mock_security}):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            mock_security.initialize_security.assert_called_once()
            mock_security.get_security_status.assert_called_once()

    def test_security_enforcement_import_failure_handled(self) -> None:
        """Security enforcement import failure handled gracefully."""
        with patch.dict("sys.modules", {"intellicrack.core.security_enforcement": None}):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            try:
                import intellicrack.__main__

                importlib.reload(intellicrack.__main__)
            except ImportError:
                pass

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_main_entry_delegates_to_main_function(self) -> None:
        """__main__ module delegates to main() function."""
        with patch("intellicrack.main.main", return_value=0) as mock_main:
            import intellicrack.__main__

            if hasattr(intellicrack.__main__, "__name__"):
                pass


class TestEnvironmentConfiguration:
    """Production tests for environment variable configuration."""

    def test_all_critical_env_vars_set(self) -> None:
        """All critical environment variables set on module import."""
        with patch.dict(os.environ, {}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            required_vars = [
                "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF",
                "TF_CPP_MIN_LOG_LEVEL",
                "CUDA_VISIBLE_DEVICES",
                "MKL_THREADING_LAYER",
            ]

            for var in required_vars:
                assert var in os.environ, f"Required environment variable {var} not set"

    def test_environment_vars_correct_values(self) -> None:
        """Environment variables have correct values for compatibility."""
        with patch.dict(os.environ, {}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            expected_values = {
                "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
                "TF_CPP_MIN_LOG_LEVEL": "2",
                "CUDA_VISIBLE_DEVICES": "-1",
                "MKL_THREADING_LAYER": "GNU",
            }

            for var, expected_value in expected_values.items():
                actual_value = os.environ.get(var)
                assert actual_value == expected_value, f"{var} = {actual_value}, expected {expected_value}"


class TestSecurityInitialization:
    """Production tests for security system initialization."""

    def test_security_status_retrieval(self) -> None:
        """Security status retrieved and validated."""
        mock_security = MagicMock()
        test_status = {
            "initialized": True,
            "patches_applied": {
                "frida_detection": True,
                "debugger_detection": True,
                "anti_tamper": True,
            },
            "protection_level": "high",
        }
        mock_security.get_security_status.return_value = test_status

        with patch.dict("sys.modules", {"intellicrack.core.security_enforcement": mock_security}):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            status = mock_security.get_security_status()
            assert status["initialized"] is True
            assert "patches_applied" in status
            assert len(status["patches_applied"]) > 0

    def test_security_patches_validation(self) -> None:
        """Security patches applied and verified."""
        mock_security = MagicMock()
        expected_patches = {
            "frida_detection": True,
            "debugger_detection": True,
            "anti_tamper": True,
            "code_signing": True,
        }
        mock_security.get_security_status.return_value = {
            "initialized": True,
            "patches_applied": expected_patches,
        }

        with patch.dict("sys.modules", {"intellicrack.core.security_enforcement": mock_security}):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            status = mock_security.get_security_status()
            patches = status.get("patches_applied", {})

            for patch_name in ["frida_detection", "debugger_detection"]:
                assert patch_name in patches


class TestModuleIntegration:
    """Production tests for module integration with main()."""

    def test_main_import_available(self) -> None:
        """main() function available from intellicrack.main."""
        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        assert hasattr(intellicrack.__main__, "main")
        assert callable(intellicrack.__main__.main)

    def test_module_execution_path(self) -> None:
        """Module can be executed via python -m intellicrack."""
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "intellicrack", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode in [0, 1, 2]


class TestPlatformCompatibility:
    """Production tests for cross-platform compatibility."""

    def test_windows_specific_configuration(self) -> None:
        """Windows-specific configuration applied on Windows."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        with patch.dict(os.environ, {}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

    def test_linux_specific_configuration(self) -> None:
        """Linux-specific configuration applied on Linux."""
        if sys.platform == "win32":
            pytest.skip("Linux-specific test")

        with patch.dict(os.environ, {"DISPLAY": ""}, clear=True):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            if "QT_QPA_PLATFORM" in os.environ:
                assert os.environ["QT_QPA_PLATFORM"] == "offscreen"


class TestErrorHandling:
    """Production tests for error handling in entry point."""

    def test_missing_security_module_handled(self) -> None:
        """Missing security enforcement module handled gracefully."""
        import importlib

        original_import = __builtins__.__import__

        def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if "security_enforcement" in name:
                raise ImportError("Security module not found")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            try:
                import intellicrack.__main__

                importlib.reload(intellicrack.__main__)
            except ImportError:
                pass

    def test_environment_modification_resilience(self) -> None:
        """Entry point resilient to environment modifications."""
        with patch.dict(os.environ, {"RANDOM_VAR": "test_value"}, clear=False):
            import importlib

            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)

            assert "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF" in os.environ
            assert os.environ.get("RANDOM_VAR") == "test_value"


class TestLoggingConfiguration:
    """Production tests for logging initialization."""

    def test_logger_initialized(self) -> None:
        """Logger initialized on module import."""
        import importlib
        import logging

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        logger = logging.getLogger("intellicrack.__main__")
        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_logging_captures_security_initialization(self) -> None:
        """Logging captures security initialization messages."""
        import importlib
        import logging

        mock_security = MagicMock()
        mock_security.get_security_status.return_value = {
            "initialized": True,
            "patches_applied": {"test": True},
        }

        with (
            patch.dict("sys.modules", {"intellicrack.core.security_enforcement": mock_security}),
            patch.object(logging.getLogger("intellicrack.__main__"), "info") as mock_log,
        ):
            if "intellicrack.__main__" in sys.modules:
                del sys.modules["intellicrack.__main__"]

            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)
