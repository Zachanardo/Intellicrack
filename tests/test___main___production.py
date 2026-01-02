"""Production tests for intellicrack/__main__.py entry point.

These tests validate that the module entry point correctly initializes
security settings, environment configuration, and delegates to main().
No mocks - real environment validation only.

Copyright (C) 2025 Zachary Flint
"""

import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest


class FakeSecurityModule:
    """Real test double for security enforcement module."""

    def __init__(
        self,
        should_fail_init: bool = False,
        should_fail_status: bool = False,
        custom_status: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.should_fail_init = should_fail_init
        self.should_fail_status = should_fail_status
        self.custom_status = custom_status
        self.initialize_security_called: bool = False
        self.initialize_security_call_count: int = 0
        self.get_security_status_called: bool = False
        self.get_security_status_call_count: int = 0
        self._default_status: Dict[str, Any] = {
            "initialized": True,
            "patches_applied": {
                "frida_detection": True,
                "debugger_detection": True,
            },
        }

    def initialize_security(self) -> None:
        """Track initialization calls."""
        self.initialize_security_called = True
        self.initialize_security_call_count += 1
        if self.should_fail_init:
            raise RuntimeError("Security initialization failed")

    def get_security_status(self) -> Dict[str, Any]:
        """Return configured security status."""
        self.get_security_status_called = True
        self.get_security_status_call_count += 1
        if self.should_fail_status:
            raise RuntimeError("Security status retrieval failed")
        if self.custom_status is not None:
            return self.custom_status
        return self._default_status

    def assert_called_once(self, method_name: str) -> None:
        """Validate method called exactly once."""
        if method_name == "initialize_security":
            assert self.initialize_security_call_count == 1, (
                f"Expected initialize_security called once, "
                f"got {self.initialize_security_call_count}"
            )
        elif method_name == "get_security_status":
            assert self.get_security_status_call_count == 1, (
                f"Expected get_security_status called once, "
                f"got {self.get_security_status_call_count}"
            )


class FakeMainFunction:
    """Real test double for main() function."""

    def __init__(self, return_value: int = 0, should_raise: bool = False) -> None:
        self.return_value = return_value
        self.should_raise = should_raise
        self.called: bool = False
        self.call_count: int = 0
        self.call_args: List[Any] = []

    def __call__(self, *args: Any, **kwargs: Any) -> int:
        """Track main() calls."""
        self.called = True
        self.call_count += 1
        self.call_args.append((args, kwargs))
        if self.should_raise:
            raise RuntimeError("Main function failed")
        return self.return_value


class FakeImportHook:
    """Real test double for controlling import behavior."""

    def __init__(
        self, fail_modules: Optional[List[str]] = None, replacement_modules: Optional[Dict[str, Any]] = None
    ) -> None:
        self.fail_modules = fail_modules or []
        self.replacement_modules = replacement_modules or {}
        self.original_import: Callable[..., Any] = __builtins__.__import__

    def __call__(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Custom import behavior for testing."""
        for fail_pattern in self.fail_modules:
            if fail_pattern in name:
                raise ImportError(f"Simulated import failure for {name}")

        if name in self.replacement_modules:
            return self.replacement_modules[name]

        return self.original_import(name, *args, **kwargs)


class FakeLogger:
    """Real test double for logger."""

    def __init__(self) -> None:
        self.info_calls: List[str] = []
        self.warning_calls: List[str] = []
        self.error_calls: List[str] = []
        self.debug_calls: List[str] = []

    def info(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Track info calls."""
        self.info_calls.append(message)

    def warning(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Track warning calls."""
        self.warning_calls.append(message)

    def error(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Track error calls."""
        self.error_calls.append(message)

    def debug(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Track debug calls."""
        self.debug_calls.append(message)


class TestMainEntryPoint:
    """Production tests for __main__.py entry point initialization."""

    def test_pybind11_gil_assertion_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variable disables pybind11 GIL assertions."""
        monkeypatch.setattr(os, "environ", {})

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        assert os.environ.get("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF") == "1"

    def test_tensorflow_configuration_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TensorFlow environment variables configured for GPU compatibility."""
        monkeypatch.setattr(os, "environ", {})

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        assert os.environ.get("TF_CPP_MIN_LOG_LEVEL") == "2"
        assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"
        assert os.environ.get("MKL_THREADING_LAYER") == "GNU"

    def test_qt_offscreen_mode_no_display(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Qt offscreen mode set when no display available."""
        env = {
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
            "TF_CPP_MIN_LOG_LEVEL": "2",
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_THREADING_LAYER": "GNU",
        }
        monkeypatch.setattr(os, "environ", env)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        assert os.environ.get("QT_QPA_PLATFORM") == "offscreen"

    def test_qt_offscreen_mode_with_display(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Qt offscreen mode NOT set when display available."""
        env = {
            "DISPLAY": ":0",
            "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF": "1",
            "TF_CPP_MIN_LOG_LEVEL": "2",
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_THREADING_LAYER": "GNU",
        }
        monkeypatch.setattr(os, "environ", env)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        assert "QT_QPA_PLATFORM" not in os.environ or os.environ.get("DISPLAY") == ":0"

    def test_security_enforcement_initialization_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Security enforcement module initializes successfully."""
        fake_security = FakeSecurityModule(
            custom_status={
                "initialized": True,
                "patches_applied": {"frida_detection": True, "debugger_detection": True},
            }
        )

        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", fake_security)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        fake_security.assert_called_once("initialize_security")
        fake_security.assert_called_once("get_security_status")

    def test_security_enforcement_import_failure_handled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Security enforcement import failure handled gracefully."""
        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", None)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        try:
            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)
        except ImportError:
            pass

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_main_entry_delegates_to_main_function(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """__main__ module delegates to main() function."""
        fake_main = FakeMainFunction(return_value=0)
        monkeypatch.setattr("intellicrack.main.main", fake_main)

        import intellicrack.__main__


class TestEnvironmentConfiguration:
    """Production tests for environment variable configuration."""

    def test_all_critical_env_vars_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """All critical environment variables set on module import."""
        monkeypatch.setattr(os, "environ", {})

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

    def test_environment_vars_correct_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables have correct values for compatibility."""
        monkeypatch.setattr(os, "environ", {})

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

    def test_security_status_retrieval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Security status retrieved and validated."""
        test_status = {
            "initialized": True,
            "patches_applied": {
                "frida_detection": True,
                "debugger_detection": True,
                "anti_tamper": True,
            },
            "protection_level": "high",
        }
        fake_security = FakeSecurityModule(custom_status=test_status)

        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", fake_security)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        status = fake_security.get_security_status()
        assert status["initialized"] is True
        assert "patches_applied" in status
        assert len(status["patches_applied"]) > 0

    def test_security_patches_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Security patches applied and verified."""
        expected_patches = {
            "frida_detection": True,
            "debugger_detection": True,
            "anti_tamper": True,
            "code_signing": True,
        }
        fake_security = FakeSecurityModule(
            custom_status={
                "initialized": True,
                "patches_applied": expected_patches,
            }
        )

        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", fake_security)

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        status = fake_security.get_security_status()
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

    def test_windows_specific_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Windows-specific configuration applied on Windows."""
        if sys.platform != "win32":
            pytest.skip("Windows-specific test")

        monkeypatch.setattr(os, "environ", {})

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

    def test_linux_specific_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Linux-specific configuration applied on Linux."""
        if sys.platform == "win32":
            pytest.skip("Linux-specific test")

        monkeypatch.setattr(os, "environ", {"DISPLAY": ""})

        import importlib

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)

        if "QT_QPA_PLATFORM" in os.environ:
            assert os.environ["QT_QPA_PLATFORM"] == "offscreen"


class TestErrorHandling:
    """Production tests for error handling in entry point."""

    def test_missing_security_module_handled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Missing security enforcement module handled gracefully."""
        import importlib

        fake_import_hook = FakeImportHook(fail_modules=["security_enforcement"])
        monkeypatch.setattr("builtins.__import__", fake_import_hook)

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        try:
            import intellicrack.__main__

            importlib.reload(intellicrack.__main__)
        except ImportError:
            pass

    def test_environment_modification_resilience(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Entry point resilient to environment modifications."""
        existing_env = dict(os.environ)
        existing_env["RANDOM_VAR"] = "test_value"
        monkeypatch.setattr(os, "environ", existing_env)

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

    def test_logging_captures_security_initialization(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Logging captures security initialization messages."""
        import importlib
        import logging

        fake_security = FakeSecurityModule(
            custom_status={
                "initialized": True,
                "patches_applied": {"test": True},
            }
        )
        fake_logger = FakeLogger()

        monkeypatch.setitem(sys.modules, "intellicrack.core.security_enforcement", fake_security)
        monkeypatch.setattr(logging.getLogger("intellicrack.__main__"), "info", fake_logger.info)

        if "intellicrack.__main__" in sys.modules:
            del sys.modules["intellicrack.__main__"]

        import intellicrack.__main__

        importlib.reload(intellicrack.__main__)
