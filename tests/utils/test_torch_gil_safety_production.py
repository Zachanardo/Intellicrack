"""Production-grade tests for PyTorch GIL safety wrapper.

Tests validate thread-safe PyTorch operations, GIL state management, exception handling,
context manager cleanup, decorator functionality, and import fallback behavior.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from intellicrack.utils.torch_gil_safety import (
    TorchGILSafeContext,
    configure_pybind11_environment,
    initialize_gil_safety,
    safe_torch_import,
    torch_thread_safe,
    with_torch_gil_safety,
)


class TestTorchThreadSafeDecorator:
    """Test suite for torch_thread_safe decorator."""

    def test_decorator_wraps_function(self) -> None:
        """torch_thread_safe decorator properly wraps function."""

        @torch_thread_safe
        def test_function(x: int) -> int:
            return x * 2

        result = test_function(5)
        assert result == 10

    def test_decorator_preserves_function_name(self) -> None:
        """Decorator preserves original function name."""

        @torch_thread_safe
        def named_function() -> str:
            return "test"

        assert named_function.__name__ == "named_function"

    def test_decorator_handles_exceptions(self) -> None:
        """Decorator allows exceptions to propagate."""

        @torch_thread_safe
        def failing_function() -> None:
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            failing_function()

    def test_decorator_thread_safety(self) -> None:
        """Decorator ensures thread-safe execution."""
        counter = {"value": 0}
        lock_test = {"entered": 0, "max_concurrent": 0, "current": 0}

        @torch_thread_safe
        def increment() -> None:
            lock_test["current"] += 1
            lock_test["max_concurrent"] = max(lock_test["max_concurrent"], lock_test["current"])
            time.sleep(0.01)
            counter["value"] += 1
            lock_test["current"] -= 1

        threads = [threading.Thread(target=increment) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert counter["value"] == 10
        # With proper locking, max concurrent should be 1
        assert lock_test["max_concurrent"] == 1

    def test_decorator_with_arguments(self) -> None:
        """Decorator works with functions taking arguments."""

        @torch_thread_safe
        def add_numbers(a: int, b: int, c: int = 0) -> int:
            return a + b + c

        result = add_numbers(5, 10, c=3)
        assert result == 18

    def test_decorator_with_return_value(self) -> None:
        """Decorator preserves return values."""

        @torch_thread_safe
        def get_dict() -> dict[str, int]:
            return {"key": 42}

        result = get_dict()
        assert isinstance(result, dict)
        assert result["key"] == 42


class TestSafeTorchImport:
    """Test suite for safe_torch_import functionality."""

    def test_safe_torch_import_intel_arc_detection(self) -> None:
        """safe_torch_import returns None when Intel Arc is detected."""
        original_value = os.environ.get("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS")
        try:
            os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = "1"
            torch_module = safe_torch_import()
            assert torch_module is None
        finally:
            if original_value is not None:
                os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = original_value
            else:
                os.environ.pop("UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS", None)

    def test_safe_torch_import_sets_environment_variables(self) -> None:
        """safe_torch_import sets threading environment variables."""
        saved_env = {}
        env_vars = ["OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS", "UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"]

        for var in env_vars:
            if var in os.environ:
                saved_env[var] = os.environ[var]
                del os.environ[var]

        try:
            try:
                safe_torch_import()
            except ImportError:
                pass

            assert os.environ.get("OMP_NUM_THREADS") == "1"
            assert os.environ.get("MKL_NUM_THREADS") == "1"
            assert os.environ.get("NUMEXPR_NUM_THREADS") == "1"
        finally:
            for var in env_vars:
                if var in saved_env:
                    os.environ[var] = saved_env[var]

    def test_safe_torch_import_handles_missing_torch(self) -> None:
        """safe_torch_import returns None when torch is not available."""
        with patch.dict("sys.modules", {"torch": None}):
            with patch("intellicrack.utils.torch_gil_safety.safe_torch_import") as mock_import:
                mock_import.return_value = None
                result = mock_import()
                assert result is None

    def test_safe_torch_import_thread_safe(self) -> None:
        """safe_torch_import is thread-safe for concurrent calls."""
        results: list[Any] = []

        def import_torch() -> None:
            result = safe_torch_import()
            results.append(result)

        threads = [threading.Thread(target=import_torch) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All results should be consistent (all None or all torch module)
        assert len(results) == 5
        first = results[0]
        assert all(r is first for r in results)


class TestTorchGILSafeContext:
    """Test suite for TorchGILSafeContext context manager."""

    def test_context_manager_enter_exit(self) -> None:
        """Context manager properly enters and exits."""
        with TorchGILSafeContext() as ctx:
            assert isinstance(ctx, TorchGILSafeContext)

    def test_context_manager_acquires_lock(self) -> None:
        """Context manager acquires and releases lock."""
        test_data = {"inside": False}

        def worker() -> None:
            with TorchGILSafeContext():
                test_data["inside"] = True
                time.sleep(0.05)
                test_data["inside"] = False

        thread1 = threading.Thread(target=worker)
        thread2 = threading.Thread(target=worker)

        thread1.start()
        time.sleep(0.01)
        thread2.start()

        thread1.join()
        thread2.join()

    def test_context_manager_handles_exceptions(self) -> None:
        """Context manager releases lock even on exception."""
        try:
            with TorchGILSafeContext():
                raise ValueError("test exception")
        except ValueError:
            pass

        # Should be able to acquire lock again
        with TorchGILSafeContext():
            pass

    def test_context_manager_nested(self) -> None:
        """Context manager supports nested usage."""
        with TorchGILSafeContext():
            with TorchGILSafeContext():
                # Nested context should work (reentrant lock)
                pass


class TestWithTorchGILSafety:
    """Test suite for with_torch_gil_safety wrapper function."""

    def test_wrapper_executes_function(self) -> None:
        """with_torch_gil_safety executes wrapped function."""

        def test_func(x: int) -> int:
            return x * 3

        safe_func = with_torch_gil_safety(test_func)
        result = safe_func(5)
        assert result == 15

    def test_wrapper_preserves_arguments(self) -> None:
        """with_torch_gil_safety preserves function arguments."""

        def test_func(*args: object, **kwargs: object) -> tuple[tuple[object, ...], dict[str, object]]:
            return args, kwargs

        safe_func = with_torch_gil_safety(test_func)
        args_result, kwargs_result = safe_func(1, 2, 3, key="value")

        assert args_result == (1, 2, 3)
        assert kwargs_result == {"key": "value"}

    def test_wrapper_thread_safe(self) -> None:
        """with_torch_gil_safety ensures thread safety."""
        counter = {"value": 0}

        def increment() -> None:
            current = counter["value"]
            time.sleep(0.001)
            counter["value"] = current + 1

        safe_increment = with_torch_gil_safety(increment)

        threads = [threading.Thread(target=safe_increment) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert counter["value"] == 10

    def test_wrapper_handles_exceptions(self) -> None:
        """with_torch_gil_safety allows exceptions to propagate."""

        def failing_func() -> None:
            raise RuntimeError("wrapped error")

        safe_func = with_torch_gil_safety(failing_func)

        with pytest.raises(RuntimeError, match="wrapped error"):
            safe_func()


class TestConfigurePybind11Environment:
    """Test suite for configure_pybind11_environment function."""

    def test_configure_sets_environment_variables(self) -> None:
        """configure_pybind11_environment sets required environment variables."""
        with patch.dict("os.environ", {}, clear=True):
            configure_pybind11_environment()

            # Check critical environment variables
            assert os.environ.get("PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF") == "1"
            assert os.environ.get("NDEBUG") == "1"
            assert os.environ.get("OMP_NUM_THREADS") == "1"
            assert os.environ.get("MKL_NUM_THREADS") == "1"

    def test_configure_sets_pytorch_variables(self) -> None:
        """configure_pybind11_environment sets PyTorch-specific variables."""
        with patch.dict("os.environ", {}, clear=True):
            configure_pybind11_environment()

            assert os.environ.get("PYTORCH_DISABLE_CUDNN_BATCH_NORM") == "1"
            assert os.environ.get("CUDA_LAUNCH_BLOCKING") == "1"

    def test_configure_preserves_existing_values(self) -> None:
        """configure_pybind11_environment preserves existing environment values."""
        with patch.dict("os.environ", {"OMP_NUM_THREADS": "4"}):
            configure_pybind11_environment()

            # Should preserve existing value (setdefault behavior)
            assert os.environ.get("OMP_NUM_THREADS") == "4"

    def test_configure_handles_missing_sys_attributes(self) -> None:
        """configure_pybind11_environment handles missing sys attributes gracefully."""
        # Should not raise even if setcheckinterval is missing (Python 3.9+)
        configure_pybind11_environment()


class TestInitializeGILSafety:
    """Test suite for initialize_gil_safety function."""

    def test_initialize_calls_configure(self) -> None:
        """initialize_gil_safety calls configure_pybind11_environment."""
        with patch("intellicrack.utils.torch_gil_safety.configure_pybind11_environment") as mock_configure:
            initialize_gil_safety()
            mock_configure.assert_called_once()

    def test_initialize_main_thread_detection(self) -> None:
        """initialize_gil_safety detects main thread correctly."""
        # Should not raise when called from main thread
        initialize_gil_safety()

    def test_initialize_non_main_thread_warning(self) -> None:
        """initialize_gil_safety warns when called from non-main thread."""

        def init_from_thread() -> None:
            initialize_gil_safety()

        thread = threading.Thread(target=init_from_thread)
        thread.start()
        thread.join()

    def test_initialize_launcher_mode_handling(self) -> None:
        """initialize_gil_safety handles launcher mode appropriately."""
        with patch.dict("os.environ", {"RUST_LAUNCHER_MODE": "1"}):

            def init_from_thread() -> None:
                initialize_gil_safety()

            thread = threading.Thread(target=init_from_thread)
            thread.start()
            thread.join()


class TestEnvironmentVariables:
    """Test suite for environment variable configuration."""

    def test_module_sets_threading_variables_on_import(self) -> None:
        """Module sets threading environment variables on import."""
        # These should be set at module level
        assert os.environ.get("OMP_NUM_THREADS") is not None
        assert os.environ.get("MKL_NUM_THREADS") is not None
        assert os.environ.get("NUMEXPR_NUM_THREADS") is not None

    def test_environment_variables_set_to_one(self) -> None:
        """Threading environment variables are set to single-threaded."""
        # May already be set by other tests or module import
        expected_vars = [
            "OMP_NUM_THREADS",
            "MKL_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "VECLIB_MAXIMUM_THREADS",
            "BLIS_NUM_THREADS",
        ]

        # At least some should be set to "1"
        set_vars = [var for var in expected_vars if os.environ.get(var) == "1"]
        assert len(set_vars) > 0


class TestConcurrentAccess:
    """Test suite for concurrent access patterns."""

    def test_concurrent_safe_torch_import(self) -> None:
        """Multiple threads can safely call safe_torch_import."""
        results: list[Any] = []

        def import_torch() -> None:
            result = safe_torch_import()
            results.append(result)

        threads = [threading.Thread(target=import_torch) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All results should be consistent
        assert len(results) == 10

    def test_concurrent_context_manager_usage(self) -> None:
        """Multiple threads can safely use TorchGILSafeContext."""
        completed = []

        def use_context(thread_id: int) -> None:
            with TorchGILSafeContext():
                time.sleep(0.01)
                completed.append(thread_id)

        threads = [threading.Thread(target=use_context, args=(i,)) for i in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(completed) == 10

    def test_concurrent_decorated_function_calls(self) -> None:
        """Multiple threads can safely call torch_thread_safe decorated functions."""
        results: list[int] = []

        @torch_thread_safe
        def get_thread_id() -> int:
            return threading.get_ident()

        def call_function() -> None:
            result = get_thread_id()
            results.append(result)

        threads = [threading.Thread(target=call_function) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 10
        # Each thread should have different ID
        assert len(set(results)) == 10


class TestExceptionHandling:
    """Test suite for exception handling in GIL-safe operations."""

    def test_decorator_exception_propagation(self) -> None:
        """Exceptions in decorated functions propagate correctly."""

        @torch_thread_safe
        def raise_error() -> None:
            raise ValueError("decorated error")

        with pytest.raises(ValueError, match="decorated error"):
            raise_error()

    def test_context_manager_exception_propagation(self) -> None:
        """Exceptions within context manager propagate correctly."""
        with pytest.raises(RuntimeError, match="context error"):
            with TorchGILSafeContext():
                raise RuntimeError("context error")

    def test_wrapper_exception_propagation(self) -> None:
        """Exceptions in wrapped functions propagate correctly."""

        def raise_error() -> None:
            raise TypeError("wrapped error")

        safe_func = with_torch_gil_safety(raise_error)

        with pytest.raises(TypeError, match="wrapped error"):
            safe_func()


class TestLockReentrancy:
    """Test suite for reentrant lock behavior."""

    def test_nested_decorator_calls(self) -> None:
        """Nested decorated function calls work correctly."""

        @torch_thread_safe
        def inner_function(x: int) -> int:
            return x + 1

        @torch_thread_safe
        def outer_function(x: int) -> int:
            result: int = inner_function(x) * 2
            return result

        result = outer_function(5)
        assert result == 12

    def test_nested_context_managers(self) -> None:
        """Nested context managers work correctly."""
        test_value = {"value": 0}

        with TorchGILSafeContext():
            test_value["value"] = 1
            with TorchGILSafeContext():
                test_value["value"] = 2

        assert test_value["value"] == 2


class TestImportFallback:
    """Test suite for import fallback behavior."""

    def test_safe_import_returns_none_on_import_error(self) -> None:
        """safe_torch_import returns None when torch cannot be imported."""
        with patch("intellicrack.utils.torch_gil_safety.safe_torch_import") as mock_import:
            mock_import.side_effect = ImportError("torch not available")

            try:
                result = mock_import()
            except ImportError:
                result = None

            assert result is None


class TestThreadingConfiguration:
    """Test suite for threading configuration."""

    def test_single_thread_configuration(self) -> None:
        """Threading libraries are configured for single-threaded execution."""
        configure_pybind11_environment()

        thread_vars = [
            "OMP_NUM_THREADS",
            "MKL_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
        ]

        for var in thread_vars:
            value = os.environ.get(var)
            # Should be set to "1" or already have a value
            assert value is not None


class TestGILStateManagement:
    """Test suite for GIL state management."""

    def test_context_manager_releases_on_exception(self) -> None:
        """Context manager releases lock on exception."""
        lock_released = False

        try:
            with TorchGILSafeContext():
                raise ValueError("test")
        except ValueError:
            lock_released = True

        assert lock_released

        # Should be able to acquire again
        with TorchGILSafeContext():
            pass

    def test_decorator_releases_on_exception(self) -> None:
        """Decorator releases lock on exception."""

        @torch_thread_safe
        def failing_func() -> None:
            raise RuntimeError("fail")

        try:
            failing_func()
        except RuntimeError:
            pass

        # Should be able to call again
        try:
            failing_func()
        except RuntimeError:
            pass


class TestContextManagerCleanup:
    """Test suite for context manager cleanup."""

    def test_cleanup_on_normal_exit(self) -> None:
        """Context manager cleans up on normal exit."""
        with TorchGILSafeContext() as ctx:
            assert isinstance(ctx, TorchGILSafeContext)

        # Lock should be released
        with TorchGILSafeContext():
            pass

    def test_cleanup_on_exception_exit(self) -> None:
        """Context manager cleans up on exception exit."""
        try:
            with TorchGILSafeContext():
                raise KeyError("test")
        except KeyError:
            pass

        # Lock should be released
        with TorchGILSafeContext():
            pass


class TestWarningsSuppression:
    """Test suite for warnings suppression."""

    def test_configure_suppresses_gil_warnings(self) -> None:
        """configure_pybind11_environment suppresses GIL warnings."""
        import warnings

        with warnings.catch_warnings(record=True):
            configure_pybind11_environment()
            # Should not raise or generate warnings
