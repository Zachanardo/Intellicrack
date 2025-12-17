"""Production-Grade Tests for Incremental Analysis Engine.

Validates REAL incremental caching functionality for binary analysis optimization.
Tests actual state persistence, cache validation, and analysis resumption proving
offensive capability for efficient repeated license protection analysis.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.analysis.incremental_analyzer import (
    get_cache_path,
    run_incremental_analysis,
)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for cache files."""
    return tmp_path


@pytest.fixture
def test_binary(temp_dir: Path) -> Path:
    """Create test binary for analysis caching."""
    binary_path = temp_dir / "test_app.exe"
    binary_content = b"MZ" + b"\x90" * 1000 + b"LICENSE_CHECK" + b"\x00" * 500
    binary_path.write_bytes(binary_content)
    return binary_path


@pytest.fixture
def cache_dir(temp_dir: Path) -> Path:
    """Provide cache directory."""
    cache = temp_dir / ".cache" / "incremental"
    cache.mkdir(parents=True, exist_ok=True)
    return cache


@pytest.fixture
def mock_app(test_binary: Path) -> Mock:
    """Create mock main application instance."""
    app = Mock()
    app.current_binary = str(test_binary)
    app.update_output = Mock()
    app.update_analysis_results = Mock()
    app.analysis_completed = Mock()
    app.run_selected_analysis_partial = Mock()
    return app


def test_get_cache_path_creates_consistent_hash(test_binary: Path) -> None:
    """Cache path generation creates consistent hash for same binary path."""
    path1 = get_cache_path(str(test_binary))
    path2 = get_cache_path(str(test_binary))

    assert path1 == path2
    assert path1.suffix == ".json"
    assert "incremental" in str(path1)


def test_get_cache_path_different_binaries_different_hashes(temp_dir: Path) -> None:
    """Different binary paths produce different cache paths."""
    binary1 = temp_dir / "app1.exe"
    binary2 = temp_dir / "app2.exe"

    binary1.write_bytes(b"MZ" + b"\x90" * 100)
    binary2.write_bytes(b"MZ" + b"\x90" * 100)

    path1 = get_cache_path(str(binary1))
    path2 = get_cache_path(str(binary2))

    assert path1 != path2


def test_get_cache_path_creates_directory(temp_dir: Path, test_binary: Path) -> None:
    """Cache path creation ensures parent directory exists."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))

        assert cache_path.parent.exists()
        assert cache_path.parent.name == "incremental"


def test_get_cache_path_hashes_absolute_path(test_binary: Path) -> None:
    """Cache path hashing uses absolute path for consistency."""
    abs_path = str(test_binary.resolve())
    cache_path = get_cache_path(abs_path)

    expected_hash = hashlib.sha256(abs_path.encode()).hexdigest()
    assert expected_hash in str(cache_path)


def test_run_incremental_analysis_no_binary_loaded(mock_app: Mock) -> None:
    """Analysis fails gracefully when no binary is loaded."""
    mock_app.current_binary = None

    run_incremental_analysis(mock_app)

    mock_app.update_output.emit.assert_called_once()
    call_args = mock_app.update_output.emit.call_args[0][0]
    assert "Error" in call_args
    assert "No binary loaded" in call_args


def test_run_incremental_analysis_cache_miss_triggers_full_analysis(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Missing or invalid cache triggers full comprehensive analysis."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_called_once_with("comprehensive")

        assert any(
            "No valid cache" in str(call)
            for call in mock_app.update_output.emit.call_args_list
        )


def test_run_incremental_analysis_valid_cache_loads_results(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Valid cache loads results without running full analysis."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size,
            "results": {
                "protection_detected": "VMProtect",
                "license_type": "trial",
                "analysis_timestamp": time.time(),
            },
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_not_called()

        mock_app.update_analysis_results.emit.assert_called_once()
        emitted_results = mock_app.update_analysis_results.emit.call_args[0][0]
        assert "VMProtect" in emitted_results


def test_run_incremental_analysis_cache_invalidation_on_modification(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache invalidates when binary modification time changes."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        old_mtime = test_binary.stat().st_mtime - 1000

        cached_data = {
            "mtime": old_mtime,
            "size": test_binary.stat().st_size,
            "results": {"protection_detected": "Old_Analysis"},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_called_once()


def test_run_incremental_analysis_cache_invalidation_on_size_change(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache invalidates when binary size changes."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size - 100,
            "results": {"protection_detected": "Old_Analysis"},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_called_once()


def test_run_incremental_analysis_emits_completion_signal(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Analysis emits completion signal when loading from cache."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size,
            "results": {"test": "data"},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.analysis_completed.emit.assert_called_once_with(
            "Incremental Analysis (Cached)"
        )


def test_run_incremental_analysis_handles_corrupted_cache(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Analysis handles corrupted cache gracefully and runs full analysis."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cache_path.write_text("INVALID JSON{]", encoding="utf-8")

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_called_once()


def test_run_incremental_analysis_handles_missing_cache_fields(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Analysis handles incomplete cache data and runs full analysis."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_called_once()


def test_run_incremental_analysis_handles_exception(
    mock_app: Mock, test_binary: Path
) -> None:
    """Analysis handles exceptions gracefully during execution."""
    with patch("intellicrack.core.analysis.incremental_analyzer.Path") as mock_path:
        mock_path.side_effect = Exception("Test exception")

        run_incremental_analysis(mock_app)

        assert any(
            "error occurred" in str(call).lower()
            for call in mock_app.update_output.emit.call_args_list
        )


def test_run_incremental_analysis_without_analysis_function(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Analysis reports error when app lacks analysis function."""
    mock_app.run_selected_analysis_partial = None

    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        run_incremental_analysis(mock_app)

        assert any(
            "not available" in str(call)
            for call in mock_app.update_output.emit.call_args_list
        )


def test_cache_preserves_complex_analysis_results(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache correctly serializes and deserializes complex analysis data."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        complex_results = {
            "protections": ["VMProtect", "Themida"],
            "license_checks": [
                {"address": "0x401000", "type": "registry"},
                {"address": "0x402000", "type": "file"},
            ],
            "metadata": {
                "analysis_version": "2.0",
                "confidence": 0.95,
                "bypass_suggestions": ["patch_0x401000", "nop_range_0x402000"],
            },
        }

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size,
            "results": complex_results,
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        emitted_results = mock_app.update_analysis_results.emit.call_args[0][0]
        parsed_results = json.loads(emitted_results)

        assert "VMProtect" in parsed_results["protections"]
        assert "Themida" in parsed_results["protections"]
        assert len(parsed_results["license_checks"]) == 2
        assert parsed_results["metadata"]["confidence"] == 0.95


def test_cache_directory_created_if_not_exists(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache directory is created automatically if it doesn't exist."""
    cache_base = temp_dir / "new_cache_dir"

    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(cache_base)

        cache_path = get_cache_path(str(test_binary))

        assert cache_path.parent.exists()
        assert cache_path.parent.name == "incremental"


def test_cache_validation_mtime_precision(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache validation uses precise modification time comparison."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        exact_mtime = test_binary.stat().st_mtime

        cached_data = {
            "mtime": exact_mtime,
            "size": test_binary.stat().st_size,
            "results": {"protection": "test"},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        mock_app.run_selected_analysis_partial.assert_not_called()


def test_cache_stores_analysis_timestamp(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache can include analysis timestamps in results."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        analysis_time = time.time()

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size,
            "results": {
                "analysis_timestamp": analysis_time,
                "binary_name": "test_app.exe",
            },
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        emitted_results = mock_app.update_analysis_results.emit.call_args[0][0]
        parsed = json.loads(emitted_results)

        assert "analysis_timestamp" in parsed
        assert abs(parsed["analysis_timestamp"] - analysis_time) < 1


def test_multiple_binaries_independent_caches(temp_dir: Path) -> None:
    """Different binaries maintain independent cache entries."""
    binary1 = temp_dir / "app1.exe"
    binary2 = temp_dir / "app2.exe"

    binary1.write_bytes(b"MZ" + b"\x90" * 100)
    binary2.write_bytes(b"MZ" + b"\x90" * 200)

    cache1 = get_cache_path(str(binary1))
    cache2 = get_cache_path(str(binary2))

    assert cache1 != cache2
    assert cache1.parent == cache2.parent


def test_cache_path_filesystem_safe(test_binary: Path) -> None:
    """Cache path uses filesystem-safe hash encoding."""
    cache_path = get_cache_path(str(test_binary))

    assert cache_path.name.replace(".json", "").isalnum()


def test_run_incremental_analysis_cache_hit_status_message(
    mock_app: Mock, test_binary: Path, temp_dir: Path
) -> None:
    """Cache hit emits clear status message to user."""
    with patch("intellicrack.core.analysis.incremental_analyzer.get_config") as mock_config:
        mock_config.return_value.get.return_value = str(temp_dir / ".cache")

        cache_path = get_cache_path(str(test_binary))
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        cached_data = {
            "mtime": test_binary.stat().st_mtime,
            "size": test_binary.stat().st_size,
            "results": {},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cached_data, f)

        run_incremental_analysis(mock_app)

        status_messages = [
            call[0][0] for call in mock_app.update_output.emit.call_args_list
        ]

        assert any("Loading cached results" in msg for msg in status_messages)
        assert any("test_app.exe" in msg for msg in status_messages)
