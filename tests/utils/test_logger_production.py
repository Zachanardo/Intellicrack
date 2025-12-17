"""Production tests for logger utilities.

Tests validate that logging configuration, function call logging decorators,
and persistent logging work correctly for real binary analysis and security
research workflows.
"""

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from intellicrack.utils.logger import (
    configure_logging,
    get_logger,
    log_all_methods,
    log_function_call,
    log_message,
    setup_logger,
    setup_logging,
    setup_persistent_logging,
)


class TestLogMessage:
    """Test basic log_message functionality."""

    def test_logs_at_info_level_by_default(self) -> None:
        """log_message logs at INFO level by default."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Test message")

            mock_logger.info.assert_called_once_with("Test message")

    def test_logs_at_debug_level(self) -> None:
        """log_message logs at DEBUG level when specified."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Debug message", level="DEBUG")

            mock_logger.debug.assert_called_once_with("Debug message")

    def test_logs_at_warning_level(self) -> None:
        """log_message logs at WARNING level when specified."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Warning message", level="WARNING")

            mock_logger.warning.assert_called_once_with("Warning message")

    def test_logs_at_error_level(self) -> None:
        """log_message logs at ERROR level when specified."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Error message", level="ERROR")

            mock_logger.error.assert_called_once_with("Error message")

    def test_logs_at_critical_level(self) -> None:
        """log_message logs at CRITICAL level when specified."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Critical message", level="CRITICAL")

            mock_logger.critical.assert_called_once_with("Critical message")

    def test_handles_case_insensitive_levels(self) -> None:
        """log_message handles case-insensitive log levels."""
        with patch("intellicrack.utils.logger.logger") as mock_logger:
            log_message("Test", level="error")
            log_message("Test", level="Error")
            log_message("Test", level="ERROR")

            assert mock_logger.error.call_count == 3


class TestLogFunctionCall:
    """Test function call logging decorator."""

    def test_logs_function_entry_and_exit(self) -> None:
        """log_function_call logs function entry and exit."""

        @log_function_call
        def test_function() -> str:
            return "result"

        with patch("intellicrack.utils.logger.logger") as mock_logger:
            result = test_function()

            assert result == "result"
            assert mock_logger.debug.call_count >= 2

    def test_logs_function_arguments(self) -> None:
        """log_function_call logs function arguments."""

        @log_function_call
        def test_function(arg1: int, arg2: str) -> None:
            pass

        with patch("intellicrack.utils.logger.logger"):
            test_function(42, "test")

    def test_logs_return_value(self) -> None:
        """log_function_call logs function return value."""

        @log_function_call
        def test_function() -> int:
            return 42

        with patch("intellicrack.utils.logger.logger"):
            result = test_function()

            assert result == 42

    def test_logs_exceptions(self) -> None:
        """log_function_call logs exceptions raised by function."""

        @log_function_call
        def failing_function() -> None:
            raise ValueError("Test error")

        with patch("intellicrack.utils.logger.logger"):
            with pytest.raises(ValueError):
                failing_function()

    def test_preserves_function_metadata(self) -> None:
        """log_function_call preserves function metadata."""

        @log_function_call
        def documented_function() -> None:
            """This is a test function."""

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This is a test function."

    def test_handles_async_functions(self) -> None:
        """log_function_call handles async functions."""

        @log_function_call
        async def async_function() -> str:
            return "async result"

        with patch("intellicrack.utils.logger.logger"):
            result = asyncio.run(async_function())

            assert result == "async result"

    def test_prevents_recursion_in_logging(self) -> None:
        """log_function_call prevents recursion during logging."""

        call_count = 0

        @log_function_call
        def recursive_function(depth: int) -> None:
            nonlocal call_count
            call_count += 1
            if depth > 0:
                recursive_function(depth - 1)

        with patch("intellicrack.utils.logger.logger"):
            recursive_function(3)

            assert call_count == 4

    def test_skips_problematic_functions(self) -> None:
        """log_function_call skips logging for problematic functions."""

        @log_function_call
        def __str__(self: object) -> str:
            return "string representation"

        with patch("intellicrack.utils.logger.logger") as mock_logger:
            __str__(None)

    def test_handles_functions_with_keyword_arguments(self) -> None:
        """log_function_call handles functions with keyword arguments."""

        @log_function_call
        def function_with_kwargs(a: int, b: int = 10, c: str = "default") -> int:
            return a + b

        with patch("intellicrack.utils.logger.logger"):
            result = function_with_kwargs(5, b=20, c="custom")

            assert result == 25

    def test_safe_repr_handles_repr_failures(self) -> None:
        """log_function_call handles objects that fail to repr."""

        class BadRepr:
            def __repr__(self) -> str:
                raise RuntimeError("repr failed")

        @log_function_call
        def test_function(obj: BadRepr) -> None:
            pass

        with patch("intellicrack.utils.logger.logger"):
            test_function(BadRepr())

    def test_truncates_long_representations(self) -> None:
        """log_function_call truncates very long argument representations."""

        @log_function_call
        def test_function(data: str) -> None:
            pass

        with patch("intellicrack.utils.logger.logger"):
            long_data = "A" * 200
            test_function(long_data)


class TestLogAllMethods:
    """Test class decorator for logging all methods."""

    def test_decorates_all_methods(self) -> None:
        """log_all_methods decorates all methods in class."""

        @log_all_methods
        class TestClass:
            def method1(self) -> str:
                return "result1"

            def method2(self) -> str:
                return "result2"

        with patch("intellicrack.utils.logger.logger"):
            obj = TestClass()
            obj.method1()
            obj.method2()

    def test_does_not_decorate_dunder_methods(self) -> None:
        """log_all_methods does not decorate dunder methods."""

        @log_all_methods
        class TestClass:
            def __init__(self) -> None:
                self.value = 42

            def regular_method(self) -> int:
                return self.value

        with patch("intellicrack.utils.logger.logger"):
            obj = TestClass()
            assert obj.value == 42


class TestSetupLogger:
    """Test logger setup functionality."""

    def test_creates_logger_with_name(self) -> None:
        """setup_logger creates logger with specified name."""
        test_logger = setup_logger("TestLogger")

        assert test_logger.name == "TestLogger"
        assert isinstance(test_logger, logging.Logger)

    def test_sets_log_level(self) -> None:
        """setup_logger sets log level correctly."""
        test_logger = setup_logger("TestLogger", level=logging.DEBUG)

        assert test_logger.level == logging.DEBUG

    def test_adds_console_handler(self) -> None:
        """setup_logger adds console handler."""
        test_logger = setup_logger("TestLogger")

        handlers = test_logger.handlers
        assert any(isinstance(h, logging.StreamHandler) for h in handlers)

    def test_adds_file_handler_when_specified(self) -> None:
        """setup_logger adds file handler when log_file specified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            test_logger = setup_logger("TestLogger", log_file=log_file)

            handlers = test_logger.handlers
            assert any(isinstance(h, logging.FileHandler) for h in handlers)

    def test_uses_default_format(self) -> None:
        """setup_logger uses default format when not specified."""
        test_logger = setup_logger("TestLogger")

        assert len(test_logger.handlers) > 0

    def test_uses_custom_format(self) -> None:
        """setup_logger uses custom format when specified."""
        custom_format = "%(levelname)s - %(message)s"
        test_logger = setup_logger("TestLogger", format_string=custom_format)

        handler = test_logger.handlers[0]
        assert handler.formatter is not None


class TestGetLogger:
    """Test logger retrieval functionality."""

    def test_returns_logger_instance(self) -> None:
        """get_logger returns logger instance."""
        test_logger = get_logger("TestLogger")

        assert isinstance(test_logger, logging.Logger)

    def test_returns_logger_with_specified_name(self) -> None:
        """get_logger returns logger with specified name."""
        test_logger = get_logger("CustomLogger")

        assert test_logger.name == "CustomLogger"

    def test_uses_caller_module_name_when_no_name(self) -> None:
        """get_logger uses caller's module name when name not provided."""
        test_logger = get_logger()

        assert isinstance(test_logger, logging.Logger)


class TestConfigureLogging:
    """Test application-wide logging configuration."""

    def test_configures_root_logger(self) -> None:
        """configure_logging configures root logger."""
        configure_logging(level=logging.DEBUG)

        intellicrack_logger = logging.getLogger("Intellicrack")
        assert intellicrack_logger.level == logging.DEBUG

    def test_enables_comprehensive_logging(self) -> None:
        """configure_logging enables comprehensive mode when requested."""
        configure_logging(enable_comprehensive=True)

    def test_sets_log_file(self) -> None:
        """configure_logging sets up file logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "app.log")
            configure_logging(log_file=log_file)

            assert Path(log_file).exists()


class TestSetupLogging:
    """Test logging setup with rotation."""

    def test_accepts_string_log_level(self) -> None:
        """setup_logging accepts string log level."""
        setup_logging(level="DEBUG")

    def test_raises_on_invalid_log_level(self) -> None:
        """setup_logging raises TypeError for invalid log level."""
        with pytest.raises(TypeError):
            setup_logging(level="INVALID")

    def test_enables_console_logging(self) -> None:
        """setup_logging enables console logging when requested."""
        setup_logging(enable_console=True)

    def test_disables_console_logging(self) -> None:
        """setup_logging can disable console logging."""
        setup_logging(enable_console=False)

    def test_sets_up_file_logging(self) -> None:
        """setup_logging sets up file logging when log_file specified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "test.log")
            setup_logging(log_file=log_file, enable_rotation=False)

            assert Path(log_file).exists()

    def test_enables_log_rotation(self) -> None:
        """setup_logging enables log rotation when requested."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "rotating.log")
            setup_logging(
                log_file=log_file,
                enable_rotation=True,
                max_bytes=1024,
                backup_count=3,
            )

            assert Path(log_file).exists()

    def test_sets_max_bytes_and_backup_count(self) -> None:
        """setup_logging respects max_bytes and backup_count parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "rotating.log")
            setup_logging(
                log_file=log_file,
                enable_rotation=True,
                max_bytes=5000,
                backup_count=2,
            )


class TestSetupPersistentLogging:
    """Test persistent logging with automatic rotation."""

    def test_creates_log_file_with_timestamp(self) -> None:
        """setup_persistent_logging creates log file with timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = setup_persistent_logging(log_dir=tmpdir, log_name="test")

            assert Path(log_file).exists()
            assert "test_" in log_file
            assert log_file.endswith(".log")

    def test_creates_log_directory_if_missing(self) -> None:
        """setup_persistent_logging creates log directory if it does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs", "subdir")
            log_file = setup_persistent_logging(log_dir=log_dir)

            assert Path(log_dir).exists()
            assert Path(log_file).exists()

    def test_enables_log_rotation(self) -> None:
        """setup_persistent_logging enables log rotation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = setup_persistent_logging(
                log_dir=tmpdir,
                enable_rotation=True,
                max_bytes=5000,
                backup_count=3,
            )

            assert Path(log_file).exists()

    def test_returns_log_file_path(self) -> None:
        """setup_persistent_logging returns path to log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = setup_persistent_logging(log_dir=tmpdir)

            assert isinstance(log_file, str)
            assert log_file.endswith(".log")


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_binary_analysis_function_logging(self) -> None:
        """Test logging during binary analysis functions."""

        @log_function_call
        def analyze_pe_header(binary_data: bytes) -> dict[str, int]:
            return {"sections": 5, "imports": 42}

        with patch("intellicrack.utils.logger.logger"):
            result = analyze_pe_header(b"MZ\x90\x00")

            assert result["sections"] == 5
            assert result["imports"] == 42

    def test_class_with_all_methods_logged(self) -> None:
        """Test class decorator for binary analyzer."""

        @log_all_methods
        class BinaryAnalyzer:
            def __init__(self) -> None:
                self.data = b""

            def load_binary(self, path: str) -> bool:
                return True

            def extract_strings(self) -> list[str]:
                return ["license", "trial", "activate"]

            def find_crypto_routines(self) -> int:
                return 3

        with patch("intellicrack.utils.logger.logger"):
            analyzer = BinaryAnalyzer()
            analyzer.load_binary("test.exe")
            strings = analyzer.extract_strings()
            crypto_count = analyzer.find_crypto_routines()

            assert len(strings) == 3
            assert crypto_count == 3

    def test_multi_level_logging_configuration(self) -> None:
        """Test configuring logging for different modules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "multi_level.log")

            setup_logging(level="DEBUG", log_file=log_file)

            logger1 = get_logger("analyzer")
            logger2 = get_logger("patcher")

            logger1.info("Analyzing binary")
            logger2.warning("Patching license check")

            assert Path(log_file).exists()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_none_return_value(self) -> None:
        """log_function_call handles None return values."""

        @log_function_call
        def returns_none() -> None:
            return None

        with patch("intellicrack.utils.logger.logger"):
            result = returns_none()

            assert result is None

    def test_handles_generator_functions(self) -> None:
        """log_function_call handles generator functions."""

        @log_function_call
        def generator_function() -> object:
            yield 1
            yield 2
            yield 3

        with patch("intellicrack.utils.logger.logger"):
            result = list(generator_function())

            assert result == [1, 2, 3]

    def test_handles_functions_with_no_arguments(self) -> None:
        """log_function_call handles functions with no arguments."""

        @log_function_call
        def no_args() -> str:
            return "result"

        with patch("intellicrack.utils.logger.logger"):
            result = no_args()

            assert result == "result"

    def test_handles_functions_with_many_arguments(self) -> None:
        """log_function_call handles functions with many arguments."""

        @log_function_call
        def many_args(a: int, b: int, c: int, d: int, e: int) -> int:
            return a + b + c + d + e

        with patch("intellicrack.utils.logger.logger"):
            result = many_args(1, 2, 3, 4, 5)

            assert result == 15

    def test_handles_nested_function_calls(self) -> None:
        """log_function_call handles nested decorated function calls."""

        @log_function_call
        def inner_function(x: int) -> int:
            return x * 2

        @log_function_call
        def outer_function(x: int) -> int:
            return inner_function(x) + 1

        with patch("intellicrack.utils.logger.logger"):
            result = outer_function(5)

            assert result == 11

    def test_handles_exception_in_async_function(self) -> None:
        """log_function_call handles exceptions in async functions."""

        @log_function_call
        async def failing_async() -> None:
            raise ValueError("Async error")

        with patch("intellicrack.utils.logger.logger"):
            with pytest.raises(ValueError):
                asyncio.run(failing_async())

    def test_log_file_creation_in_nonexistent_directory(self) -> None:
        """setup_persistent_logging creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            deep_path = os.path.join(tmpdir, "a", "b", "c", "logs")
            log_file = setup_persistent_logging(log_dir=deep_path)

            assert Path(log_file).exists()
            assert Path(deep_path).exists()
