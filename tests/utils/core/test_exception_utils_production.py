"""Production tests for exception handling and secure pickle operations.

Tests validate pickle security, exception handling, config management,
and AI model loading with real security validation.

Copyright (C) 2025 Zachary Flint
"""

import hashlib
import hmac
import io
import json
import logging
import os
import pickle
import tempfile
from pathlib import Path
from types import TracebackType
from typing import Any

import pytest

from intellicrack.utils.core.exception_utils import (
    RestrictedUnpickler,
    create_sample_plugins,
    handle_exception,
    load_ai_model,
    load_config,
    save_config,
    secure_pickle_dump,
    secure_pickle_load,
    setup_file_logging,
)


class TestSecurePickleOperations:
    """Test secure pickle dump and load with integrity validation."""

    def test_secure_pickle_dump_basic_object(self, tmp_path: Path) -> None:
        """Secure pickle dump stores object with integrity check."""
        test_obj = {"key": "value", "number": 42, "list": [1, 2, 3]}
        pickle_file = tmp_path / "test_object.pkl"

        secure_pickle_dump(test_obj, str(pickle_file))

        assert pickle_file.exists()
        assert pickle_file.stat().st_size > 32

        with open(pickle_file, "rb") as f:
            mac = f.read(32)
            data = f.read()

        assert len(mac) == 32
        assert len(data) > 0

    def test_secure_pickle_load_valid_file(self, tmp_path: Path) -> None:
        """Secure pickle load retrieves object with valid integrity check."""
        test_obj = {"test": "data", "nested": {"value": 123}}
        pickle_file = tmp_path / "valid_object.pkl"

        secure_pickle_dump(test_obj, str(pickle_file))
        loaded_obj = secure_pickle_load(str(pickle_file))

        assert loaded_obj == test_obj
        assert isinstance(loaded_obj, dict)
        assert loaded_obj["test"] == "data"
        assert loaded_obj["nested"]["value"] == 123

    def test_secure_pickle_load_tampered_file_fails(self, tmp_path: Path) -> None:
        """Tampered pickle file fails integrity check."""
        test_obj = {"secure": "data"}
        pickle_file = tmp_path / "tampered.pkl"

        secure_pickle_dump(test_obj, str(pickle_file))

        with open(pickle_file, "rb") as f:
            mac = f.read(32)
            data = f.read()

        tampered_data = data + b"tampered"

        with open(pickle_file, "wb") as f:
            f.write(mac)
            f.write(tampered_data)

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_load(str(pickle_file))

    def test_secure_pickle_complex_objects(self, tmp_path: Path) -> None:
        """Secure pickle handles complex nested objects."""
        complex_obj = {
            "string": "test",
            "number": 42,
            "float": 3.14,
            "list": [1, 2, 3, 4, 5],
            "tuple": (1, 2, 3),
            "nested": {"deep": {"value": "nested_data"}},
            "mixed": [{"a": 1}, {"b": 2}],
        }

        pickle_file = tmp_path / "complex.pkl"

        secure_pickle_dump(complex_obj, str(pickle_file))
        loaded_obj = secure_pickle_load(str(pickle_file))

        assert loaded_obj == complex_obj
        assert loaded_obj["nested"]["deep"]["value"] == "nested_data"
        assert loaded_obj["mixed"][1]["b"] == 2

    def test_secure_pickle_hmac_validation(self, tmp_path: Path) -> None:
        """HMAC correctly validates pickle file integrity."""
        test_obj = {"data": "test"}
        pickle_file = tmp_path / "hmac_test.pkl"

        secure_pickle_dump(test_obj, str(pickle_file))

        with open(pickle_file, "rb") as f:
            stored_mac = f.read(32)
            data = f.read()

        from intellicrack.utils.core.exception_utils import PICKLE_SECURITY_KEY

        expected_mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

        assert hmac.compare_digest(stored_mac, expected_mac)


class TestRestrictedUnpickler:
    """Test restricted unpickler security validation."""

    def test_restricted_unpickler_allows_safe_classes(self, tmp_path: Path) -> None:
        """Restricted unpickler allows safe standard library classes."""
        safe_obj = {"list": [1, 2, 3], "dict": {"key": "value"}}

        data = pickle.dumps(safe_obj)
        unpickler = RestrictedUnpickler(io.BytesIO(data))
        loaded = unpickler.load()

        assert loaded == safe_obj

    def test_restricted_unpickler_allows_numpy_classes(self, tmp_path: Path) -> None:
        """Restricted unpickler allows numpy classes if numpy available."""
        try:
            import numpy as np

            array = np.array([1, 2, 3, 4, 5])
            data = pickle.dumps(array)

            unpickler = RestrictedUnpickler(io.BytesIO(data))
            loaded = unpickler.load()

            assert np.array_equal(loaded, array)

        except ImportError:
            pytest.skip("NumPy not available")

    def test_restricted_unpickler_allows_intellicrack_modules(self, tmp_path: Path) -> None:
        """Restricted unpickler allows intellicrack module classes."""

        class IntelllicrackTestClass:
            def __init__(self) -> None:
                self.value = 42

        test_obj = IntelllicrackTestClass()

        test_obj.__module__ = "intellicrack.test.module"

        data = pickle.dumps(test_obj)
        unpickler = RestrictedUnpickler(io.BytesIO(data))

        loaded = unpickler.load()
        assert loaded.value == 42

    def test_restricted_unpickler_blocks_dangerous_modules(self, tmp_path: Path) -> None:
        """Restricted unpickler blocks potentially dangerous modules."""

        class DangerousClass:
            def __reduce__(self) -> tuple:
                return (eval, ("print('pwned')",))

        dangerous_obj = DangerousClass()
        data = pickle.dumps(dangerous_obj)

        unpickler = RestrictedUnpickler(io.BytesIO(data))

        with pytest.raises(pickle.UnpicklingError):
            unpickler.load()


class TestExceptionHandling:
    """Test global exception handler functionality."""

    def test_handle_exception_keyboard_interrupt_passthrough(self) -> None:
        """KeyboardInterrupt passes through to default handler."""
        import sys

        original_excepthook = sys.excepthook

        try:
            exception_handled = False

            def mock_excepthook(exc_type, exc_value, exc_traceback):
                nonlocal exception_handled
                exception_handled = True

            sys.__excepthook__ = mock_excepthook

            exc_type = KeyboardInterrupt
            exc_value = KeyboardInterrupt()
            exc_traceback = None

            handle_exception(exc_type, exc_value, exc_traceback)

            assert exception_handled

        finally:
            sys.excepthook = original_excepthook

    def test_handle_exception_logs_error(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Exception handler logs errors appropriately."""
        with caplog.at_level(logging.CRITICAL):
            exc_type = ValueError
            exc_value = ValueError("Test error")
            exc_traceback = None

            handle_exception(exc_type, exc_value, exc_traceback)

            assert any("Unhandled exception" in record.message for record in caplog.records)
            assert any("ValueError" in record.message for record in caplog.records)

    def test_handle_exception_creates_error_report(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exception handler creates error report file."""
        error_log = tmp_path / "intellicrack_errors.log"

        monkeypatch.chdir(tmp_path)

        exc_type = RuntimeError
        exc_value = RuntimeError("Test runtime error")
        exc_traceback = None

        handle_exception(exc_type, exc_value, exc_traceback)

        assert error_log.exists()

        with open(error_log, encoding="utf-8") as f:
            content = f.read()

        assert "RuntimeError" in content
        assert "Test runtime error" in content


class TestConfigManagement:
    """Test configuration file loading and saving."""

    def test_save_config_creates_file(self, tmp_path: Path) -> None:
        """save_config creates JSON configuration file."""
        config_file = tmp_path / "test_config.json"
        config_data = {
            "setting1": "value1",
            "setting2": 42,
            "nested": {"key": "value"},
        }

        result = save_config(config_data, str(config_file))

        assert result is True
        assert config_file.exists()

        with open(config_file, encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded == config_data

    def test_load_config_reads_file(self, tmp_path: Path) -> None:
        """load_config reads existing JSON configuration."""
        config_file = tmp_path / "existing_config.json"
        config_data = {"key": "value", "number": 123}

        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(config_data, f)

        loaded = load_config(str(config_file))

        assert loaded == config_data
        assert loaded["key"] == "value"
        assert loaded["number"] == 123

    def test_load_config_nonexistent_file(self, tmp_path: Path) -> None:
        """load_config returns empty dict for nonexistent file."""
        config_file = tmp_path / "nonexistent.json"

        loaded = load_config(str(config_file))

        assert loaded == {}

    def test_save_config_overwrites_existing(self, tmp_path: Path) -> None:
        """save_config overwrites existing configuration."""
        config_file = tmp_path / "overwrite.json"

        old_config = {"old": "data"}
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(old_config, f)

        new_config = {"new": "data", "updated": True}
        result = save_config(new_config, str(config_file))

        assert result is True

        loaded = load_config(str(config_file))
        assert loaded == new_config
        assert "old" not in loaded

    def test_load_config_invalid_json(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """load_config handles invalid JSON gracefully."""
        config_file = tmp_path / "invalid.json"

        with open(config_file, "w", encoding="utf-8") as f:
            f.write("{invalid json content")

        with caplog.at_level(logging.ERROR):
            loaded = load_config(str(config_file))

        assert loaded == {}
        assert any("Failed to load configuration" in record.message for record in caplog.records)


class TestFileLogging:
    """Test file logging setup functionality."""

    def test_setup_file_logging_creates_handler(self, tmp_path: Path) -> None:
        """setup_file_logging creates log file and handler."""
        log_file = tmp_path / "test.log"

        logger = setup_file_logging(str(log_file), logging.INFO)

        assert logger is not None
        assert log_file.exists()

        test_message = "Test log message"
        logging.info(test_message)

        with open(log_file, encoding="utf-8") as f:
            content = f.read()

        assert test_message in content

    def test_setup_file_logging_creates_directory(self, tmp_path: Path) -> None:
        """setup_file_logging creates parent directories if needed."""
        log_dir = tmp_path / "logs" / "nested"
        log_file = log_dir / "test.log"

        logger = setup_file_logging(str(log_file))

        assert logger is not None
        assert log_dir.exists()
        assert log_file.exists()

    def test_setup_file_logging_level_filtering(self, tmp_path: Path) -> None:
        """setup_file_logging respects log level."""
        log_file = tmp_path / "level_test.log"

        logger = setup_file_logging(str(log_file), logging.WARNING)

        logging.info("Info message - should not appear")
        logging.warning("Warning message - should appear")
        logging.error("Error message - should appear")

        with open(log_file, encoding="utf-8") as f:
            content = f.read()

        assert "Warning message" in content
        assert "Error message" in content


class TestAIModelLoading:
    """Test AI model loading with security validation."""

    def test_load_ai_model_nonexistent_file(self, tmp_path: Path) -> None:
        """load_ai_model returns None for nonexistent file."""
        model_path = tmp_path / "nonexistent_model.pkl"

        result = load_ai_model(str(model_path))

        assert result is None

    def test_load_ai_model_file_size_limit(self, tmp_path: Path) -> None:
        """load_ai_model rejects files exceeding size limit."""
        large_file = tmp_path / "large_model.pkl"

        with open(large_file, "wb") as f:
            f.write(b"0" * (501 * 1024 * 1024))

        result = load_ai_model(str(large_file))

        assert result is None

    def test_load_ai_model_joblib_format(self, tmp_path: Path) -> None:
        """load_ai_model loads joblib format models."""
        try:
            import joblib

            model_data = {"type": "test_model", "weights": [1, 2, 3]}
            model_file = tmp_path / "model.joblib"

            joblib.dump(model_data, str(model_file))

            loaded = load_ai_model(str(model_file))

            assert loaded == model_data

        except ImportError:
            pytest.skip("joblib not available")

    def test_load_ai_model_pickle_format_secure(self, tmp_path: Path) -> None:
        """load_ai_model loads pickle files with security validation."""
        model_data = {"model_type": "classifier", "params": {"threshold": 0.5}}
        model_file = tmp_path / "model.pkl"

        secure_pickle_dump(model_data, str(model_file))

        loaded = load_ai_model(str(model_file))

        assert loaded == model_data
        assert loaded["model_type"] == "classifier"

    def test_load_ai_model_unsupported_format(self, tmp_path: Path) -> None:
        """load_ai_model returns None for unsupported format."""
        model_file = tmp_path / "model.unsupported"

        with open(model_file, "wb") as f:
            f.write(b"unsupported model format")

        result = load_ai_model(str(model_file))

        assert result is None


class TestPluginCreation:
    """Test sample plugin creation functionality."""

    def test_create_sample_plugins_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """create_sample_plugins creates sample plugin files."""
        plugin_dir = tmp_path / "intellicrack" / "intellicrack" / "plugins" / "custom_modules"
        monkeypatch.chdir(tmp_path)

        result = create_sample_plugins()

        assert result is True
        assert plugin_dir.exists()

        plugin_file = plugin_dir / "sample_plugin.py"
        assert plugin_file.exists()

        with open(plugin_file, encoding="utf-8") as f:
            content = f.read()

        assert "class SamplePlugin" in content
        assert "def analyze" in content
        assert "def register" in content

    def test_create_sample_plugins_content_valid(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sample plugin content is valid Python."""
        plugin_dir = tmp_path / "intellicrack" / "intellicrack" / "plugins" / "custom_modules"
        monkeypatch.chdir(tmp_path)

        create_sample_plugins()

        plugin_file = plugin_dir / "sample_plugin.py"

        with open(plugin_file, encoding="utf-8") as f:
            content = f.read()

        compile(content, str(plugin_file), "exec")


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_config_workflow(self, tmp_path: Path) -> None:
        """Complete config save, load, update workflow."""
        config_file = tmp_path / "app_config.json"

        initial_config = {
            "app_name": "Intellicrack",
            "version": "1.0.0",
            "settings": {"debug": True},
        }

        save_config(initial_config, str(config_file))
        loaded = load_config(str(config_file))

        assert loaded == initial_config

        loaded["settings"]["debug"] = False
        loaded["version"] = "1.0.1"

        save_config(loaded, str(config_file))
        updated = load_config(str(config_file))

        assert updated["version"] == "1.0.1"
        assert updated["settings"]["debug"] is False

    def test_pickle_security_workflow(self, tmp_path: Path) -> None:
        """Complete secure pickle workflow with validation."""
        model_data = {
            "model_name": "binary_classifier",
            "trained_on": "protected_binaries",
            "accuracy": 0.95,
        }

        model_file = tmp_path / "secure_model.pkl"

        secure_pickle_dump(model_data, str(model_file))

        assert model_file.exists()

        loaded = secure_pickle_load(str(model_file))

        assert loaded == model_data
        assert loaded["accuracy"] == 0.95

    def test_error_logging_workflow(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Complete error logging and reporting workflow."""
        log_dir = tmp_path / "logs"
        log_file = log_dir / "app.log"

        logger = setup_file_logging(str(log_file), logging.DEBUG)

        monkeypatch.chdir(tmp_path)

        try:
            raise ValueError("Test error for logging")
        except ValueError as e:
            logging.error("Caught error: %s", e, exc_info=True)

        with open(log_file, encoding="utf-8") as f:
            content = f.read()

        assert "ValueError" in content
        assert "Test error for logging" in content

    def test_multiple_pickle_operations(self, tmp_path: Path) -> None:
        """Multiple pickle save/load operations maintain integrity."""
        objects = [
            {"id": 1, "data": "first"},
            {"id": 2, "data": "second"},
            {"id": 3, "data": "third"},
        ]

        for i, obj in enumerate(objects):
            file_path = tmp_path / f"object_{i}.pkl"
            secure_pickle_dump(obj, str(file_path))

        for i, expected in enumerate(objects):
            file_path = tmp_path / f"object_{i}.pkl"
            loaded = secure_pickle_load(str(file_path))
            assert loaded == expected
