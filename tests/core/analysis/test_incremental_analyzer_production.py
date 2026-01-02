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
from typing import Any, Optional, Callable

import pytest

from intellicrack.core.analysis.incremental_analyzer import (
    get_cache_path,
    run_incremental_analysis,
)


class FakeSignal:
    """Real test double for Qt signal functionality."""

    def __init__(self) -> None:
        self.call_count: int = 0
        self.call_args_list: list[tuple[Any, ...]] = []
        self.last_args: Optional[tuple[Any, ...]] = None

    def emit(self, *args: Any) -> None:
        self.call_count += 1
        self.call_args_list.append(args)
        self.last_args = args

    def assert_called_once(self) -> None:
        assert self.call_count == 1, f"Expected 1 call, got {self.call_count}"

    def assert_called_once_with(self, *expected_args: Any) -> None:
        self.assert_called_once()
        assert self.last_args == expected_args, f"Expected {expected_args}, got {self.last_args}"

    def assert_not_called(self) -> None:
        assert self.call_count == 0, f"Expected 0 calls, got {self.call_count}"


class FakeMainApplication:
    """Real test double for main application instance."""

    def __init__(self, binary_path: str = "") -> None:
        self.current_binary: str = binary_path
        self.update_output: FakeSignal = FakeSignal()
        self.update_analysis_results: FakeSignal = FakeSignal()
        self.analysis_completed: FakeSignal = FakeSignal()

    def emit(self, *args: Any) -> None:
        """Emit a signal."""
        pass

    def run_selected_analysis_partial(self, analysis_type: str) -> None:
        """Run a partial analysis of the specified type."""
        pass


class FakeConfig:
    """Real test double for configuration object."""

    def __init__(self, cache_dir: str) -> None:
        self._cache_dir: str = cache_dir

    def get(self, key: str, default: Any = None) -> Any:
        if key == "cache_dir":
            return self._cache_dir
        return default


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
def fake_app(test_binary: Path) -> FakeMainApplication:
    """Create fake main application instance."""
    return FakeMainApplication(binary_path=str(test_binary))


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


def test_get_cache_path_creates_directory(temp_dir: Path, test_binary: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cache path creation ensures parent directory exists."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))

    assert cache_path.parent.exists()
    assert cache_path.parent.name == "incremental"


def test_get_cache_path_hashes_absolute_path(test_binary: Path) -> None:
    """Cache path hashing uses absolute path for consistency."""
    abs_path = str(test_binary.resolve())
    cache_path = get_cache_path(abs_path)

    expected_hash = hashlib.sha256(abs_path.encode()).hexdigest()
    assert expected_hash in str(cache_path)


def test_run_incremental_analysis_no_binary_loaded(fake_app: FakeMainApplication) -> None:
    """Analysis fails gracefully when no binary is loaded."""
    object.__setattr__(fake_app, "current_binary", None)

    run_incremental_analysis(fake_app)

    fake_app.update_output.assert_called_once()
    assert fake_app.update_output.last_args is not None
    call_args = fake_app.update_output.last_args[0]
    assert "Error" in call_args
    assert "No binary loaded" in call_args


def test_run_incremental_analysis_cache_miss_triggers_full_analysis(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing or invalid cache triggers full comprehensive analysis."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert analysis_called == ["comprehensive"]
    assert any(
        "No valid cache" in str(call)
        for call in fake_app.update_output.call_args_list
    )


def test_run_incremental_analysis_valid_cache_loads_results(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid cache loads results without running full analysis."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

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

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 0

    fake_app.update_analysis_results.assert_called_once()
    assert fake_app.update_analysis_results.last_args is not None
    emitted_results = fake_app.update_analysis_results.last_args[0]
    assert "VMProtect" in emitted_results


def test_run_incremental_analysis_cache_invalidation_on_modification(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache invalidates when binary modification time changes."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

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

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 1


def test_run_incremental_analysis_cache_invalidation_on_size_change(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache invalidates when binary size changes."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    cached_data = {
        "mtime": test_binary.stat().st_mtime,
        "size": test_binary.stat().st_size - 100,
        "results": {"protection_detected": "Old_Analysis"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cached_data, f)

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 1


def test_run_incremental_analysis_emits_completion_signal(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis emits completion signal when loading from cache."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    cached_data = {
        "mtime": test_binary.stat().st_mtime,
        "size": test_binary.stat().st_size,
        "results": {"test": "data"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cached_data, f)

    run_incremental_analysis(fake_app)

    fake_app.analysis_completed.assert_called_once_with(
        "Incremental Analysis (Cached)"
    )


def test_run_incremental_analysis_handles_corrupted_cache(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis handles corrupted cache gracefully and runs full analysis."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    cache_path.write_text("INVALID JSON{]", encoding="utf-8")

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 1


def test_run_incremental_analysis_handles_missing_cache_fields(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis handles incomplete cache data and runs full analysis."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    cached_data = {
        "mtime": test_binary.stat().st_mtime,
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cached_data, f)

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 1


def test_run_incremental_analysis_handles_exception(
    fake_app: FakeMainApplication, test_binary: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis handles exceptions gracefully during execution."""
    def raise_exception(*args: Any, **kwargs: Any) -> None:
        raise Exception("Test exception")

    import intellicrack.core.analysis.incremental_analyzer
    original_path = getattr(intellicrack.core.analysis.incremental_analyzer, "Path", None)

    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "Path", raise_exception)

    run_incremental_analysis(fake_app)

    assert any(
        "error occurred" in str(call).lower()
        for call in fake_app.update_output.call_args_list
    )


def test_run_incremental_analysis_without_analysis_function(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Analysis reports error when app lacks analysis function."""
    object.__setattr__(fake_app, "run_selected_analysis_partial", None)

    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    run_incremental_analysis(fake_app)

    assert any(
        "not available" in str(call)
        for call in fake_app.update_output.call_args_list
    )


def test_cache_preserves_complex_analysis_results(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache correctly serializes and deserializes complex analysis data."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

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

    run_incremental_analysis(fake_app)

    assert fake_app.update_analysis_results.last_args is not None
    emitted_results = fake_app.update_analysis_results.last_args[0]
    parsed_results = json.loads(emitted_results)

    assert "VMProtect" in parsed_results["protections"]
    assert "Themida" in parsed_results["protections"]
    assert len(parsed_results["license_checks"]) == 2
    assert parsed_results["metadata"]["confidence"] == 0.95


def test_cache_directory_created_if_not_exists(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache directory is created automatically if it doesn't exist."""
    cache_base = temp_dir / "new_cache_dir"

    fake_config = FakeConfig(cache_dir=str(cache_base))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))

    assert cache_path.parent.exists()
    assert cache_path.parent.name == "incremental"


def test_cache_validation_mtime_precision(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache validation uses precise modification time comparison."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

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

    analysis_called: list[str] = []

    def track_analysis(analysis_type: str) -> None:
        analysis_called.append(analysis_type)

    object.__setattr__(fake_app, "run_selected_analysis_partial", track_analysis)

    run_incremental_analysis(fake_app)

    assert len(analysis_called) == 0


def test_cache_stores_analysis_timestamp(
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache can include analysis timestamps in results."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

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

    run_incremental_analysis(fake_app)

    assert fake_app.update_analysis_results.last_args is not None
    emitted_results = fake_app.update_analysis_results.last_args[0]
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
    fake_app: FakeMainApplication, test_binary: Path, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache hit emits clear status message to user."""
    fake_config = FakeConfig(cache_dir=str(temp_dir / ".cache"))

    import intellicrack.core.analysis.incremental_analyzer
    monkeypatch.setattr(intellicrack.core.analysis.incremental_analyzer, "get_config", lambda: fake_config)

    cache_path = get_cache_path(str(test_binary))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    cached_data = {
        "mtime": test_binary.stat().st_mtime,
        "size": test_binary.stat().st_size,
        "results": {},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cached_data, f)

    run_incremental_analysis(fake_app)

    status_messages = [
        call[0] for call in fake_app.update_output.call_args_list
    ]

    assert any("Loading cached results" in msg for msg in status_messages)
    assert any("test_app.exe" in msg for msg in status_messages)
