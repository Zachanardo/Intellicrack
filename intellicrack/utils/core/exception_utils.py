"""Exception handling and error utilities for Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import pickle
import sys
import traceback
from pathlib import Path
from types import TracebackType
from typing import Any, cast

from .secure_serialization import (
    RestrictedUnpickler as BaseRestrictedUnpickler,
    secure_pickle_dump,
    secure_pickle_load,
)


logger = logging.getLogger(__name__)

QMessageBox: type[Any] | None = None
QApplication: type[Any] | None = None

try:
    from PyQt6.QtWidgets import (
        QApplication as _QApplication,
        QMessageBox as _QMessageBox,
    )

    QMessageBox = _QMessageBox
    QApplication = _QApplication
except ImportError as e:
    logger.exception("Import error in exception_utils: %s", e)


class ExceptionUnpickler(BaseRestrictedUnpickler):
    """Extended unpickler that allows exception types for exception serialization.

    Extends the base RestrictedUnpickler with additional exception classes
    needed for serializing and deserializing exception information.
    """

    EXCEPTION_CLASSES: frozenset[str] = frozenset({
        # Built-in exception types
        "Exception",
        "BaseException",
        "ValueError",
        "TypeError",
        "KeyError",
        "AttributeError",
        "RuntimeError",
        "OSError",
        "IOError",
        "FileNotFoundError",
        "PermissionError",
        "TimeoutError",
        "ConnectionError",
        "ImportError",
        "ModuleNotFoundError",
        "StopIteration",
        "GeneratorExit",
        "SystemExit",
        "KeyboardInterrupt",
        "AssertionError",
        "IndexError",
        "MemoryError",
        "RecursionError",
        "OverflowError",
        "ZeroDivisionError",
        "UnicodeError",
        "UnicodeDecodeError",
        "UnicodeEncodeError",
        # traceback safe types for exception serialization
        "TracebackException",
        "FrameSummary",
        "StackSummary",
        # types module - safe descriptor types
        "TracebackType",
        "FrameType",
        "CodeType",
        "SimpleNamespace",
        "MappingProxyType",
        "ModuleType",
    })

    EXCEPTION_MODULES: frozenset[str] = frozenset({
        "traceback",
        "types",
    })

    EXCEPTION_INTELLICRACK_CLASSES: frozenset[str] = frozenset({
        "IntellicrackError",
        "AnalysisError",
        "ProtectionError",
        "ConfigurationError",
        "NetworkError",
        "BinaryFormatError",
        "ExceptionContext",
        "ExceptionInfo",
    })

    def find_class(self, module: str, name: str) -> type[object]:
        """Override to also allow exception-related classes.

        Args:
            module: The module name of the class to unpickle.
            name: The class name to unpickle.

        Returns:
            The class object if allowed.

        Raises:
            UnpicklingError: If the class is not in the allowed list.

        """
        # Check exception-specific classes first
        if module == "builtins" and name in self.EXCEPTION_CLASSES:
            return cast("type[object]", super(BaseRestrictedUnpickler, self).find_class(module, name))

        if module in self.EXCEPTION_MODULES and name in self.EXCEPTION_CLASSES:
            return cast("type[object]", super(BaseRestrictedUnpickler, self).find_class(module, name))

        if module.startswith("intellicrack.") and name in self.EXCEPTION_INTELLICRACK_CLASSES:
            return cast("type[object]", super(BaseRestrictedUnpickler, self).find_class(module, name))

        # Fall back to base class check
        return cast("type[object]", super().find_class(module, name))


# Re-export for backward compatibility
RestrictedUnpickler = ExceptionUnpickler


def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Global exception handler for unhandled exceptions.

    Args:
        exc_type: Exception type.
        exc_value: Exception instance.
        exc_traceback: Exception traceback object.

    Returns:
        None

    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Allow Ctrl+C to work normally
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    error_msg = f"Unhandled exception: {exc_type.__name__}: {exc_value}"
    logger.critical(error_msg, exc_info=(exc_type, exc_value, exc_traceback))

    # Display error dialog if GUI is available
    _display_exception_dialog(exc_type, exc_value, exc_traceback)

    # Report error to log file
    _report_error(exc_type, exc_value, exc_traceback)


def _display_exception_dialog(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Display an exception dialog to the user.

    Args:
        exc_type: Exception type.
        exc_value: Exception instance.
        exc_traceback: Exception traceback object.

    Returns:
        None

    """
    if QMessageBox is None or QApplication is None:
        # No GUI available
        return

    if QApplication.instance() is None:
        # No application instance
        return

    try:
        error_text = f"An unexpected error occurred:\n\n{exc_type.__name__}: {exc_value}"
        detailed_text = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Critical)
        msg_box.setWindowTitle("Intellicrack Error")
        msg_box.setText(error_text)
        msg_box.setDetailedText(detailed_text)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to display exception dialog: %s", e)


def _report_error(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> None:
    """Report error to log file and optionally to remote service.

    Args:
        exc_type: Exception type.
        exc_value: Exception instance.
        exc_traceback: Exception traceback object.

    Returns:
        None

    """
    try:
        error_report = {
            "timestamp": logger.handlers[0].format(
                logging.LogRecord(
                    name="error",
                    level=logging.ERROR,
                    pathname="",
                    lineno=0,
                    msg="",
                    args=(),
                    exc_info=None,
                ),
            )
            if logger.handlers
            else str(sys.exc_info()),
            "exception_type": exc_type.__name__,
            "exception_value": str(exc_value),
            "traceback": traceback.format_exception(exc_type, exc_value, exc_traceback),
            "system_info": {
                "platform": sys.platform,
                "python_version": sys.version,
                "working_directory": str(Path.cwd()),
            },
        }

        # Write to error log file
        error_log_path = "intellicrack_errors.log"
        with open(error_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(error_report, indent=2) + "\n")

        logger.info("Error report written to %s", error_log_path)

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to write error report: %s", e)


def load_config(config_path: str = "config.json") -> dict[str, Any]:
    """Load configuration from JSON file.

    Args:
        config_path: Path to configuration file.

    Returns:
        Configuration dictionary.

    Raises:
        OSError: If the file cannot be read due to permission or I/O errors.
        ValueError: If the JSON file is malformed or contains invalid data.
        RuntimeError: If an unexpected error occurs during configuration loading.

    """
    try:
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                config: dict[str, Any] = json.load(f)
            logger.info("Configuration loaded from %s", config_path)
            return config
        logger.warning("Configuration file not found: %s", config_path)
        return {}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to load configuration: %s", e)
        return {}


def save_config(config: dict[str, Any], config_path: str = "config.json") -> bool:
    """Save configuration to JSON file.

    Args:
        config: Configuration dictionary to save.
        config_path: Path to configuration file.

    Returns:
        True if successful, False otherwise.

    """
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        logger.info("Configuration saved to %s", config_path)
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to save configuration: %s", e)
        return False


def setup_file_logging(log_file: str = "intellicrack.log", level: int = logging.INFO) -> logging.Logger:
    """Set up file logging for the application.

    Args:
        log_file: Path to log file.
        level: Logging level.

    Returns:
        Configured logger.

    """
    try:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file) or "logs"
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Set up file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        # Set up formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        file_handler.setFormatter(formatter)

        # Add handler to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        root_logger.setLevel(level)

        logger.info("File logging set up: %s", log_file)
        return root_logger

    except (OSError, ValueError, RuntimeError) as e:
        print(f"Failed to set up file logging: {e}")
        return logging.getLogger()


def create_sample_plugins() -> bool:
    """Create sample plugin files for demonstration.

    Returns:
        True if successful, False otherwise.

    """
    try:
        plugins_dir = "intellicrack/intellicrack/plugins/custom_modules"
        os.makedirs(plugins_dir, exist_ok=True)

        # Sample Python plugin
        sample_plugin = '''"""
Sample Intellicrack Plugin

This is a template for creating custom analysis plugins.
"""

class SamplePlugin:
    def __init__(self):
        self.name = "Sample Plugin"
        self.description = "A sample plugin for demonstration"
        self.version = "1.0.0"

    def analyze(self, binary_path):
        """
        Analyze the binary file.

        Args:
            binary_path: Path to binary file

        Returns:
            Analysis results
        """
        results = {
            "plugin": self.name,
            "binary": binary_path,
            "findings": [
                "Sample finding 1",
                "Sample finding 2"
            ]
        }
        return results

    def get_info(self):
        """Get plugin information."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version
        }

# Plugin registration
def register():
    return SamplePlugin()
'''

        plugin_file = os.path.join(plugins_dir, "sample_plugin.py")
        with open(plugin_file, "w", encoding="utf-8") as f:
            f.write(sample_plugin)

        logger.info("Sample plugin created: %s", plugin_file)
        return True

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to create sample plugins: %s", e)
        return False


def load_ai_model(model_path: str) -> object | None:
    """Load an AI model from file.

    Supports loading models in joblib, pickle, and ONNX formats with
    security validation to prevent loading maliciously crafted model files.

    Args:
        model_path: Path to model file (must be .joblib, .pkl, or .onnx).

    Returns:
        Loaded model object, or None if loading fails due to unsupported
        format, missing dependencies, or security restrictions.

    Raises:
        OSError: If the file cannot be accessed due to permission or I/O errors.
        ValueError: If the model file is corrupted or integrity check fails.
        RuntimeError: If an unexpected error occurs during model loading.

    """
    try:
        if not os.path.exists(model_path):
            logger.exception("Model file not found: %s", model_path)
            return None

        # Security validation
        file_size = os.path.getsize(model_path)
        max_size = 500 * 1024 * 1024  # 500MB max
        if file_size > max_size:
            logger.exception("Model file too large (%d bytes), rejecting for security", file_size)
            return None

        # Try different model formats
        if model_path.endswith(".joblib"):
            try:
                import joblib

                model: object = joblib.load(model_path)
                logger.info("Joblib model loaded: %s", model_path)
                return model
            except ImportError:
                logger.warning("joblib not available for model loading")

        elif model_path.endswith(".pkl"):
            try:
                logger.warning("Loading model with pickle - ensure file is from trusted source")

                # Additional validation for pickle files
                if hasattr(os, "stat"):
                    stat_info = Path(model_path).stat()
                    # Check file permissions - warn if world-writable
                    if stat_info.st_mode & 0o002:
                        logger.warning("Model file is world-writable - potential security risk")

                loaded_model: object = secure_pickle_load(model_path)
                logger.info("Pickle model loaded: %s", model_path)
                return loaded_model
            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Failed to load pickle model: %s", e)

        elif model_path.endswith(".onnx"):
            try:
                import onnxruntime

                onnx_model: object = onnxruntime.InferenceSession(model_path)
                logger.info("ONNX model loaded: %s", model_path)
                return onnx_model
            except ImportError:
                logger.warning("onnxruntime not available for ONNX model loading")

        logger.warning("Unsupported model format: %s", model_path)
        return None

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to load AI model: %s", e)
        return None
