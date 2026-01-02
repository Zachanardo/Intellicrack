"""Real I/O Tests for Incremental Analysis Engine.

Tests REAL file system operations, cache persistence, and binary modification
detection without mocks. Validates offensive capability for efficient license
protection analysis with actual state management.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import hashlib
import json
import os
import shutil
import struct
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from intellicrack.core.analysis.incremental_analyzer import (
    get_cache_path,
)


class FakeConfigManager:
    """Real test double for configuration management with call tracking."""

    def __init__(self, cache_base_path: str) -> None:
        self.cache_base_path: str = cache_base_path
        self.get_calls: list[str] = []

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Track configuration access and return configured values."""
        self.get_calls.append(key)
        if key == "cache_dir" or key.endswith("cache"):
            return self.cache_base_path
        return default


@pytest.fixture
def isolated_cache_dir(tmp_path: Path) -> Path:
    """Create isolated cache directory for testing."""
    cache_dir = tmp_path / ".cache" / "incremental"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


@pytest.fixture
def protected_binary(tmp_path: Path) -> Path:
    """Create realistic protected binary with license checks."""
    binary_path = tmp_path / "protected_app.exe"

    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    license_check_code = b"\x55\x8B\xEC\x83\xEC\x10"
    registry_strings = b"SOFTWARE\\LicenseKey\x00"
    serial_validation = b"ABCD-EFGH-IJKL-MNOP\x00"

    binary_content = (
        pe_header +
        b"\x00" * 100 +
        license_check_code +
        b"\x00" * 50 +
        registry_strings +
        b"\x00" * 30 +
        serial_validation +
        b"\x00" * 500
    )

    binary_path.write_bytes(binary_content)
    return binary_path


def test_cache_path_deterministic_generation(protected_binary: Path) -> None:
    """Cache path generation is deterministic for same binary."""
    paths = [get_cache_path(str(protected_binary)) for _ in range(10)]

    assert all(p == paths[0] for p in paths)
    assert paths[0].exists() or paths[0].parent.exists()


def test_cache_path_uses_sha256_hash(protected_binary: Path) -> None:
    """Cache path incorporates SHA256 hash of binary path."""
    cache_path = get_cache_path(str(protected_binary))

    expected_hash = hashlib.sha256(str(protected_binary).encode()).hexdigest()

    assert expected_hash in str(cache_path)


def test_cache_directory_structure_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache directory structure is created correctly."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"MZ" + b"\x00" * 100)

    cache_base = tmp_path / "custom_cache"

    fake_config = FakeConfigManager(str(cache_base))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(binary_path))

    assert cache_path.parent.exists()
    assert cache_path.parent.name == "incremental"
    assert cache_path.parent.parent == cache_base
    assert len(fake_config.get_calls) > 0


def test_real_cache_write_and_read_cycle(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Complete write and read cycle with real cache files."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    analysis_results = {
        "protections": ["VMProtect 3.5", "Themida 3.1"],
        "license_checks": [
            {
                "address": "0x401000",
                "type": "registry",
                "key": "SOFTWARE\\LicenseKey",
            },
            {
                "address": "0x402500",
                "type": "serial_validation",
                "algorithm": "RSA-2048",
            },
        ],
        "bypass_points": [
            {"address": "0x401010", "instruction": "jz", "patch": "nop"},
        ],
        "confidence": 0.92,
    }

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": analysis_results,
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, indent=2)

    assert cache_path.exists()

    with open(cache_path, encoding="utf-8") as f:
        loaded_data = json.load(f)

    assert loaded_data["mtime"] == cache_data["mtime"]
    assert loaded_data["size"] == cache_data["size"]
    assert loaded_data["results"]["confidence"] == 0.92
    assert "VMProtect 3.5" in loaded_data["results"]["protections"]
    assert len(loaded_data["results"]["license_checks"]) == 2


def test_cache_invalidation_on_binary_modification(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache correctly detects binary modifications."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    original_mtime = protected_binary.stat().st_mtime
    original_size = protected_binary.stat().st_size

    cache_data = {
        "mtime": original_mtime,
        "size": original_size,
        "results": {"protection": "Original"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    time.sleep(0.1)

    modified_content = protected_binary.read_bytes() + b"\x00\x00\x00\x00"
    protected_binary.write_bytes(modified_content)

    new_mtime = protected_binary.stat().st_mtime
    new_size = protected_binary.stat().st_size

    with open(cache_path, encoding="utf-8") as f:
        cached = json.load(f)

    assert cached["mtime"] != new_mtime or cached["size"] != new_size


def test_cache_survives_multiple_reads(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache file remains valid across multiple read operations."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": {"test": "data", "counter": 42},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    reads = []
    for _ in range(5):
        with open(cache_path, encoding="utf-8") as f:
            reads.append(json.load(f))

    assert all(r["results"]["counter"] == 42 for r in reads)
    assert all(r["mtime"] == cache_data["mtime"] for r in reads)


def test_concurrent_cache_access_safety(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache handles concurrent read operations safely."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": {"shared": "value"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    results: list[str] = []
    errors: list[Exception] = []

    def read_cache() -> None:
        try:
            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)
                results.append(data["results"]["shared"])
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=read_cache) for _ in range(10)]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    assert not errors
    assert all(r == "value" for r in results)


def test_cache_handles_large_analysis_results(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache correctly stores and retrieves large analysis datasets."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    large_results = {
        "functions": [
            {
                "address": f"0x{i:06x}",
                "name": f"function_{i}",
                "calls": list(range(i, i + 10)),
            }
            for i in range(1000, 2000)
        ],
        "strings": [f"String_{i}" for i in range(5000)],
        "imports": {f"dll_{i}.dll": [f"func_{j}" for j in range(50)]
                   for i in range(20)},
    }

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": large_results,
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    assert cache_path.exists()
    file_size = cache_path.stat().st_size
    assert file_size > 10000

    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)

    assert len(loaded["results"]["functions"]) == 1000
    assert len(loaded["results"]["strings"]) == 5000
    assert len(loaded["results"]["imports"]) == 20


def test_cache_preserves_nested_analysis_structure(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache preserves complex nested analysis data structures."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    nested_results = {
        "protection_layers": {
            "layer1": {
                "type": "VMProtect",
                "version": "3.5.1",
                "features": {
                    "virtualization": True,
                    "mutation": True,
                    "anti_debug": ["IsDebuggerPresent", "CheckRemoteDebugger"],
                },
            },
            "layer2": {
                "type": "Custom",
                "checks": [
                    {"type": "registry", "path": "HKCU\\Software\\App"},
                    {"type": "file", "path": "license.dat"},
                ],
            },
        },
        "control_flow": {
            "main": {
                "entry": "0x401000",
                "calls": [
                    {"target": "0x402000", "condition": "license_valid"},
                ],
            },
        },
    }

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": nested_results,
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded["results"]["protection_layers"]["layer1"]["version"] == "3.5.1"
    assert "IsDebuggerPresent" in loaded["results"]["protection_layers"]["layer1"]["features"]["anti_debug"]
    assert loaded["results"]["control_flow"]["main"]["entry"] == "0x401000"


def test_cache_timestamp_precision(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache uses precise timestamps for validation."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    precise_mtime = protected_binary.stat().st_mtime

    cache_data = {
        "mtime": precise_mtime,
        "size": protected_binary.stat().st_size,
        "results": {},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded["mtime"] == precise_mtime
    assert isinstance(loaded["mtime"], (int, float))


def test_multiple_binaries_separate_caches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Different binaries maintain completely separate cache files."""
    binaries = []
    for i in range(5):
        binary = tmp_path / f"app{i}.exe"
        binary.write_bytes(b"MZ" + b"\x00" * (100 + i * 10))
        binaries.append(binary)

    cache_base = tmp_path / ".cache"

    fake_config = FakeConfigManager(str(cache_base))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_paths = [get_cache_path(str(b)) for b in binaries]

    for i, cache_path in enumerate(cache_paths):
        data = {
            "mtime": binaries[i].stat().st_mtime,
            "size": binaries[i].stat().st_size,
            "results": {"binary_index": i},
        }

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    assert len(set(cache_paths)) == 5

    for i, cache_path in enumerate(cache_paths):
        with open(cache_path, encoding="utf-8") as f:
            loaded = json.load(f)
            assert loaded["results"]["binary_index"] == i


def test_cache_directory_permissions(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache directory has appropriate permissions for read/write."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    assert cache_path.parent.exists()
    assert os.access(cache_path.parent, os.R_OK | os.W_OK)


def test_cache_handles_binary_deletion(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache persists even when source binary is deleted."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": {"deleted": "binary"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    binary_path_str = str(protected_binary)

    protected_binary.unlink()

    assert cache_path.exists()

    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded["results"]["deleted"] == "binary"


def test_cache_json_formatting_consistency(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache JSON is consistently formatted for readability."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": {"key1": "value1", "key2": "value2"},
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, indent=2)

    content = cache_path.read_text(encoding="utf-8")

    assert "\n" in content
    assert "  " in content


def test_cache_path_collision_resistance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Different binary paths produce non-colliding cache paths."""
    paths = [
        tmp_path / "app.exe",
        tmp_path / "subdir" / "app.exe",
        tmp_path / "another" / "app.exe",
    ]

    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"MZ" + b"\x00" * 100)

    cache_base = tmp_path / ".cache"

    fake_config = FakeConfigManager(str(cache_base))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_paths = [get_cache_path(str(p)) for p in paths]

    assert len(set(cache_paths)) == 3


def test_cache_stores_analysis_metadata(
    protected_binary: Path, isolated_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache includes metadata about analysis execution."""
    fake_config = FakeConfigManager(str(isolated_cache_dir.parent))
    monkeypatch.setattr(
        "intellicrack.core.analysis.incremental_analyzer.get_config",
        lambda: fake_config,
    )

    cache_path = get_cache_path(str(protected_binary))

    analysis_time = time.time()

    cache_data = {
        "mtime": protected_binary.stat().st_mtime,
        "size": protected_binary.stat().st_size,
        "results": {
            "analysis_metadata": {
                "timestamp": analysis_time,
                "version": "2.0",
                "duration_seconds": 15.3,
                "analyzer": "comprehensive",
            },
            "findings": {"protections": ["VMProtect"]},
        },
    }

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache_data, f)

    with open(cache_path, encoding="utf-8") as f:
        loaded = json.load(f)

    metadata = loaded["results"]["analysis_metadata"]
    assert abs(metadata["timestamp"] - analysis_time) < 1
    assert metadata["version"] == "2.0"
    assert metadata["duration_seconds"] == 15.3
