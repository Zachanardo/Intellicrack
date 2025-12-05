"""Production-Grade Tests for Analysis Cache Module.

Validates real caching functionality for protection analysis results with
persistence, size management, automatic invalidation, and concurrent access.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import hmac
import json
import os
import pickle
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Generator

import pytest

from intellicrack.protection.analysis_cache import (
    AnalysisCache,
    CacheEntry,
    CacheStats,
    RestrictedUnpickler,
    clear_analysis_cache,
    get_analysis_cache,
    secure_pickle_dump,
    secure_pickle_load,
)


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    cache_dir = tmp_path / "test_cache"
    cache_dir.mkdir(exist_ok=True)
    return cache_dir


@pytest.fixture
def test_binary_path(tmp_path: Path) -> Path:
    binary_path = tmp_path / "test_binary.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)
    return binary_path


@pytest.fixture
def real_pe_binary(tmp_path: Path) -> Path:
    pe_header = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"PE\x00\x00"
    )
    pe_binary = pe_header + b"\x00" * 2000
    binary_path = tmp_path / "protected_app.exe"
    binary_path.write_bytes(pe_binary)
    return binary_path


@pytest.fixture
def analysis_cache(temp_cache_dir: Path) -> Generator[AnalysisCache, None, None]:
    os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
    cache = AnalysisCache(
        cache_dir=str(temp_cache_dir),
        max_entries=100,
        max_size_mb=10,
        auto_save=False,
    )
    yield cache
    cache.clear()
    os.environ.pop("DISABLE_BACKGROUND_THREADS", None)


@pytest.fixture
def sample_analysis_result() -> dict[str, Any]:
    return {
        "protections": ["VMProtect", "Themida"],
        "is_packed": True,
        "confidence": 95.0,
        "entropy": 7.8,
        "sections": [".vmp0", ".vmp1"],
        "serial_validation_address": 0x401000,
        "license_check_function": 0x402500,
    }


@pytest.fixture
def complex_analysis_result() -> dict[str, Any]:
    return {
        "protections": ["VMProtect 3.5", "Themida 3.1", "Code Virtualizer"],
        "is_packed": True,
        "is_obfuscated": True,
        "confidence": 98.5,
        "entropy": 7.95,
        "sections": [".vmp0", ".vmp1", ".themida", ".text", ".data"],
        "import_table": {
            "kernel32.dll": ["GetProcAddress", "LoadLibraryA", "VirtualProtect"],
            "advapi32.dll": ["RegOpenKeyExA", "RegQueryValueExA"],
        },
        "serial_validation": {
            "algorithm": "RSA-2048",
            "location": 0x401000,
            "call_sites": [0x403210, 0x405678, 0x408900],
        },
        "license_server": {
            "endpoints": ["https://activate.example.com/verify"],
            "protocol": "HTTPS with custom encryption",
        },
        "anti_debug": ["IsDebuggerPresent", "NtQueryInformationProcess", "Hardware breakpoints"],
        "trial_mechanism": {"registry_key": "HKLM\\Software\\App\\InstallDate", "days_remaining": 30},
    }


class TestSecurePickle:
    def test_secure_pickle_dump_creates_file_with_hmac(self, tmp_path: Path) -> None:
        test_data = {"test": "data", "numbers": [1, 2, 3]}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))

        assert file_path.exists()
        content = file_path.read_bytes()
        assert len(content) > 32
        assert len(content) == 32 + len(pickle.dumps(test_data))

    def test_secure_pickle_load_validates_integrity(self, tmp_path: Path) -> None:
        test_data = {"analysis": "result", "confidence": 95.5}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))
        loaded_data = secure_pickle_load(str(file_path))

        assert loaded_data == test_data
        assert loaded_data["confidence"] == 95.5

    def test_secure_pickle_load_detects_tampering(self, tmp_path: Path) -> None:
        test_data = {"analysis": "result"}
        file_path = tmp_path / "test_pickle.pkl"

        secure_pickle_dump(test_data, str(file_path))

        content = file_path.read_bytes()
        tampered = content[:32] + b"TAMPERED" + content[40:]
        file_path.write_bytes(tampered)

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_load(str(file_path))

    def test_secure_pickle_handles_large_data(self, tmp_path: Path) -> None:
        large_data = {
            "protections": ["VMProtect"] * 100,
            "binary_data": b"\x00" * 50000,
            "strings": ["test" * 1000 for _ in range(100)],
        }
        file_path = tmp_path / "large_pickle.pkl"

        secure_pickle_dump(large_data, str(file_path))
        loaded = secure_pickle_load(str(file_path))

        assert loaded == large_data
        assert len(loaded["binary_data"]) == 50000

    def test_secure_pickle_preserves_nested_structures(self, tmp_path: Path) -> None:
        nested_data = {
            "level1": {
                "level2": {
                    "level3": {"license_check": 0x401000, "serial_algo": "RSA-2048"},
                    "protections": ["VMProtect", "Themida"],
                },
                "entropy": [7.1, 7.5, 7.9, 8.0],
            },
        }
        file_path = tmp_path / "nested_pickle.pkl"

        secure_pickle_dump(nested_data, str(file_path))
        loaded = secure_pickle_load(str(file_path))

        assert loaded == nested_data
        assert loaded["level1"]["level2"]["level3"]["license_check"] == 0x401000

    def test_restricted_unpickler_blocks_unsafe_classes(self, tmp_path: Path) -> None:
        class UnsafeClass:
            def __reduce__(self) -> tuple[type, tuple[str]]:
                return (os.system, ("echo hacked",))

        unsafe_obj = UnsafeClass()
        pickled = pickle.dumps(unsafe_obj)

        file_path = tmp_path / "unsafe.pkl"
        mac = hmac.new(os.environ.get("INTELLICRACK_PICKLE_KEY", "default-key-change-me").encode(), pickled, hashlib.sha256).digest()
        file_path.write_bytes(mac + pickled)

        with pytest.raises(pickle.UnpicklingError):
            secure_pickle_load(str(file_path))

    def test_restricted_unpickler_blocks_subprocess_execution(self, tmp_path: Path) -> None:
        import subprocess

        malicious_data = pickle.dumps((subprocess.Popen, (["calc.exe"],)))
        file_path = tmp_path / "malicious.pkl"

        mac = hmac.new(os.environ.get("INTELLICRACK_PICKLE_KEY", "default-key-change-me").encode(), malicious_data, hashlib.sha256).digest()
        file_path.write_bytes(mac + malicious_data)

        with pytest.raises(pickle.UnpicklingError):
            secure_pickle_load(str(file_path))

    def test_restricted_unpickler_allows_safe_modules(self, tmp_path: Path) -> None:
        import datetime

        safe_data = {
            "timestamp": datetime.datetime.now(),
            "data": [1, 2, 3],
            "dict": {"key": "value"},
        }

        file_path = tmp_path / "safe.pkl"
        secure_pickle_dump(safe_data, str(file_path))

        loaded = secure_pickle_load(str(file_path))
        assert isinstance(loaded["timestamp"], datetime.datetime)
        assert loaded["data"] == [1, 2, 3]

    def test_secure_pickle_preserves_cache_data_structures(self, tmp_path: Path) -> None:
        cache_data = {
            "protections": ["VMProtect", "Themida"],
            "metadata": {
                "timestamp": time.time(),
                "file_mtime": 123456.789,
                "file_size": 1024,
            },
            "analysis_results": {
                "entropy": 7.95,
                "serial_check": 0x401000,
            },
        }

        file_path = tmp_path / "cache_data.pkl"
        secure_pickle_dump(cache_data, str(file_path))

        loaded = secure_pickle_load(str(file_path))
        assert loaded["metadata"]["file_size"] == 1024
        assert loaded["protections"] == ["VMProtect", "Themida"]


class TestCacheEntry:
    def test_cache_entry_tracks_access_statistics(self, test_binary_path: Path) -> None:
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=time.time(),
            file_mtime=test_binary_path.stat().st_mtime,
            file_size=test_binary_path.stat().st_size,
        )

        assert entry.access_count == 0
        assert entry.last_access == 0.0

        entry.update_access()
        assert entry.access_count == 1
        assert entry.last_access > 0

        time.sleep(0.01)
        entry.update_access()
        assert entry.access_count == 2

    def test_cache_entry_validates_file_existence(self, tmp_path: Path) -> None:
        file_path = tmp_path / "test.exe"
        file_path.write_bytes(b"test")

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=file_path.stat().st_mtime,
            file_size=len(b"test"),
        )

        assert entry.is_valid(str(file_path))

        file_path.unlink()
        assert not entry.is_valid(str(file_path))

    def test_cache_entry_detects_file_modifications(self, test_binary_path: Path) -> None:
        original_mtime = test_binary_path.stat().st_mtime

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=original_mtime,
            file_size=test_binary_path.stat().st_size,
        )

        assert entry.is_valid(str(test_binary_path))

        time.sleep(0.1)
        test_binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 1024)

        assert not entry.is_valid(str(test_binary_path))

    def test_cache_entry_detects_size_changes(self, tmp_path: Path) -> None:
        file_path = tmp_path / "test.exe"
        file_path.write_bytes(b"original")

        entry = CacheEntry(
            data={},
            timestamp=time.time(),
            file_mtime=file_path.stat().st_mtime,
            file_size=len(b"original"),
        )

        assert entry.is_valid(str(file_path))

        file_path.write_bytes(b"modified_longer_content")
        assert not entry.is_valid(str(file_path))

    def test_cache_entry_detects_subtle_modifications(self, tmp_path: Path) -> None:
        file_path = tmp_path / "app.exe"
        original_content = b"MZ\x90\x00" + b"\x00" * 10000
        file_path.write_bytes(original_content)

        entry = CacheEntry(
            data={"protection": "VMProtect"},
            timestamp=time.time(),
            file_mtime=file_path.stat().st_mtime,
            file_size=len(original_content),
        )

        assert entry.is_valid(str(file_path))

        time.sleep(0.05)
        modified_content = b"MZ\x90\x00" + b"\xFF" * 10000
        file_path.write_bytes(modified_content)

        assert not entry.is_valid(str(file_path))

    def test_cache_entry_access_statistics_multiple_threads(self, test_binary_path: Path) -> None:
        entry = CacheEntry(
            data={"test": "data"},
            timestamp=time.time(),
            file_mtime=test_binary_path.stat().st_mtime,
            file_size=test_binary_path.stat().st_size,
        )

        def update_worker() -> None:
            for _ in range(50):
                entry.update_access()

        threads = [threading.Thread(target=update_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert entry.access_count == 250


class TestCacheStats:
    def test_cache_stats_calculates_hit_rate(self) -> None:
        stats = CacheStats(cache_hits=75, cache_misses=25)

        assert stats.hit_rate == 75.0

    def test_cache_stats_handles_zero_requests(self) -> None:
        stats = CacheStats(cache_hits=0, cache_misses=0)

        assert stats.hit_rate == 0.0

    def test_cache_stats_handles_all_misses(self) -> None:
        stats = CacheStats(cache_hits=0, cache_misses=100)

        assert stats.hit_rate == 0.0

    def test_cache_stats_handles_all_hits(self) -> None:
        stats = CacheStats(cache_hits=100, cache_misses=0)

        assert stats.hit_rate == 100.0

    def test_cache_stats_converts_to_dict(self) -> None:
        stats = CacheStats(
            total_entries=100,
            cache_hits=80,
            cache_misses=20,
            cache_invalidations=5,
            total_size_bytes=1024000,
            oldest_entry=1234567890.0,
            newest_entry=1234567900.0,
        )

        result = stats.to_dict()

        assert isinstance(result, dict)
        assert result["total_entries"] == 100
        assert result["cache_hits"] == 80
        assert result["cache_misses"] == 20
        assert result["cache_invalidations"] == 5
        assert result["total_size_bytes"] == 1024000
        assert "hit_rate" not in result

    def test_cache_stats_json_serializable(self) -> None:
        stats = CacheStats(total_entries=50, cache_hits=40, cache_misses=10)

        stats_dict = stats.to_dict()
        json_str = json.dumps(stats_dict)

        assert json_str is not None
        parsed = json.loads(json_str)
        assert parsed["total_entries"] == 50


class TestAnalysisCacheInitialization:
    def test_cache_initialization_creates_directory(self, temp_cache_dir: Path) -> None:
        cache_dir = temp_cache_dir / "new_cache"
        assert not cache_dir.exists()

        cache = AnalysisCache(cache_dir=str(cache_dir))

        assert cache_dir.exists()
        assert cache.cache_dir == cache_dir

    def test_cache_initialization_with_custom_limits(self, temp_cache_dir: Path) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=500,
            max_size_mb=50,
            auto_save=True,
        )

        assert cache.max_entries == 500
        assert cache.max_size_bytes == 50 * 1024 * 1024
        assert cache.auto_save is True

    def test_cache_initialization_uses_default_directory(self) -> None:
        cache = AnalysisCache()

        assert cache.cache_dir.exists()
        assert ".intellicrack" in str(cache.cache_dir)
        assert "cache" in str(cache.cache_dir)

        cache.clear()

    def test_cache_initialization_creates_cache_files(self, temp_cache_dir: Path) -> None:
        cache = AnalysisCache(cache_dir=str(temp_cache_dir))

        cache_file = cache.cache_dir / "analysis_cache.pkl"
        stats_file = cache.cache_dir / "cache_stats.json"

        assert cache.cache_file == cache_file
        assert cache.stats_file == stats_file


class TestAnalysisCacheStorage:
    def test_cache_stores_and_retrieves_analysis_results(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
        sample_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(test_binary_path), sample_analysis_result)

        result = analysis_cache.get(str(test_binary_path))

        assert result is not None
        assert result == sample_analysis_result
        assert result["protections"] == ["VMProtect", "Themida"]
        assert result["confidence"] == 95.0
        assert result["serial_validation_address"] == 0x401000

    def test_cache_stores_complex_analysis_results(
        self,
        analysis_cache: AnalysisCache,
        real_pe_binary: Path,
        complex_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(real_pe_binary), complex_analysis_result)

        result = analysis_cache.get(str(real_pe_binary))

        assert result is not None
        assert len(result["protections"]) == 3
        assert "VMProtect 3.5" in result["protections"]
        assert result["serial_validation"]["algorithm"] == "RSA-2048"
        assert len(result["serial_validation"]["call_sites"]) == 3
        assert "IsDebuggerPresent" in result["anti_debug"]

    def test_cache_stores_multiple_different_binaries(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        binaries = []
        for i in range(10):
            binary_path = tmp_path / f"app_{i}.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + bytes([i]) * 1000)
            binaries.append(binary_path)

            analysis_cache.put(
                str(binary_path),
                {"app_id": i, "protection": f"Protection_{i}"},
            )

        for i, binary_path in enumerate(binaries):
            result = analysis_cache.get(str(binary_path))
            assert result is not None
            assert result["app_id"] == i
            assert result["protection"] == f"Protection_{i}"

    def test_cache_miss_returns_none(self, analysis_cache: AnalysisCache) -> None:
        result = analysis_cache.get("/nonexistent/file.exe")

        assert result is None

    def test_cache_respects_scan_options_in_key(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        result1 = {"scan": "quick", "depth": 1}
        result2 = {"scan": "deep", "depth": 5}
        result3 = {"scan": "comprehensive", "depth": 10}

        analysis_cache.put(str(test_binary_path), result1, "quick")
        analysis_cache.put(str(test_binary_path), result2, "deep")
        analysis_cache.put(str(test_binary_path), result3, "comprehensive")

        assert analysis_cache.get(str(test_binary_path), "quick") == result1
        assert analysis_cache.get(str(test_binary_path), "deep") == result2
        assert analysis_cache.get(str(test_binary_path), "comprehensive") == result3
        assert analysis_cache.get(str(test_binary_path), "") != result1

    def test_cache_handles_binary_data_in_results(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        binary_analysis = {
            "protection": "VMProtect",
            "extracted_code": b"\x55\x8B\xEC\x83\xEC\x10",
            "signature": bytes.fromhex("4D5A9000"),
        }

        analysis_cache.put(str(test_binary_path), binary_analysis)
        result = analysis_cache.get(str(test_binary_path))

        assert result is not None
        assert result["extracted_code"] == b"\x55\x8B\xEC\x83\xEC\x10"
        assert result["signature"] == b"MZ\x90\x00"


class TestCacheInvalidation:
    def test_cache_invalidates_on_file_modification(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
        sample_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(test_binary_path), sample_analysis_result)
        assert analysis_cache.get(str(test_binary_path)) is not None

        time.sleep(0.1)
        test_binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 2048)

        result = analysis_cache.get(str(test_binary_path))
        assert result is None

    def test_cache_invalidates_on_file_deletion(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        binary_path = tmp_path / "temp_app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        analysis_cache.put(str(binary_path), {"data": "test"})
        assert analysis_cache.get(str(binary_path)) is not None

        binary_path.unlink()

        result = analysis_cache.get(str(binary_path))
        assert result is None

    def test_cache_tracks_invalidation_statistics(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        binary_path = tmp_path / "app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        analysis_cache.put(str(binary_path), {"data": "test"})

        time.sleep(0.1)
        binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 1000)

        analysis_cache.get(str(binary_path))

        stats = analysis_cache.get_stats()
        assert stats.cache_invalidations >= 1

    def test_cache_cleanup_removes_invalid_entries(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        file1 = tmp_path / "file1.exe"
        file2 = tmp_path / "file2.exe"
        file3 = tmp_path / "file3.exe"
        file1.write_bytes(b"data1")
        file2.write_bytes(b"data2")
        file3.write_bytes(b"data3")

        analysis_cache.put(str(file1), {"data": 1})
        analysis_cache.put(str(file2), {"data": 2})
        analysis_cache.put(str(file3), {"data": 3})

        file1.unlink()
        file3.unlink()

        removed_count = analysis_cache.cleanup_invalid()

        assert removed_count >= 2
        assert analysis_cache.get(str(file1)) is None
        assert analysis_cache.get(str(file2)) is not None
        assert analysis_cache.get(str(file3)) is None


class TestCacheStatistics:
    def test_cache_tracks_hit_and_miss_statistics(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})

        analysis_cache.get(str(test_binary_path))
        analysis_cache.get(str(test_binary_path))
        analysis_cache.get("/nonexistent1.exe")
        analysis_cache.get("/nonexistent2.exe")

        stats = analysis_cache.get_stats()

        assert stats.cache_hits >= 2
        assert stats.cache_misses >= 2
        assert stats.total_entries >= 1

    def test_cache_calculates_hit_rate_correctly(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        binary_path = tmp_path / "app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        analysis_cache.put(str(binary_path), {"data": "test"})

        for _ in range(80):
            analysis_cache.get(str(binary_path))

        for i in range(20):
            analysis_cache.get(f"/nonexistent_{i}.exe")

        stats = analysis_cache.get_stats()
        assert stats.hit_rate >= 75.0
        assert stats.hit_rate <= 85.0

    def test_cache_tracks_entry_count(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        for i in range(10):
            binary_path = tmp_path / f"app_{i}.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + bytes([i]) * 100)
            analysis_cache.put(str(binary_path), {"id": i})

        stats = analysis_cache.get_stats()
        assert stats.total_entries == 10

    def test_cache_get_cache_info_returns_detailed_information(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})
        analysis_cache.get(str(test_binary_path))
        analysis_cache.get(str(test_binary_path))

        info = analysis_cache.get_cache_info()

        assert "stats" in info
        assert "cache_size_mb" in info
        assert "cache_directory" in info
        assert "max_entries" in info
        assert "max_size_mb" in info
        assert "top_entries" in info
        assert len(info["top_entries"]) > 0
        assert info["top_entries"][0]["access_count"] >= 2


class TestCacheEviction:
    def test_cache_evicts_lru_entries_when_entry_limit_reached(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=10,
            max_size_mb=100,
            auto_save=False,
        )

        for i in range(20):
            cache.put(f"/file_{i}.exe", {"index": i})
            if i < 10:
                time.sleep(0.01)

        stats = cache.get_stats()
        assert stats.total_entries <= 10

    def test_cache_evicts_when_size_limit_exceeded(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=1000,
            max_size_mb=1,
            auto_save=False,
        )

        large_data = {"data": "x" * 100000}

        for i in range(20):
            cache.put(f"/file_{i}.exe", large_data)

        size_mb = cache._get_cache_size_mb()
        assert size_mb <= 2.0

    def test_cache_evicts_least_recently_accessed(
        self,
        temp_cache_dir: Path,
        tmp_path: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=5,
            max_size_mb=100,
            auto_save=False,
        )

        old_file = tmp_path / "old.exe"
        old_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
        cache.put(str(old_file), {"type": "old"})

        time.sleep(0.05)

        for i in range(10):
            new_file = tmp_path / f"new_{i}.exe"
            new_file.write_bytes(b"MZ\x90\x00" + bytes([i]) * 100)
            cache.put(str(new_file), {"type": "new", "id": i})

        result = cache.get(str(old_file))
        assert result is None

    def test_cache_preserves_frequently_accessed_entries(
        self,
        temp_cache_dir: Path,
        tmp_path: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=5,
            max_size_mb=100,
            auto_save=False,
        )

        hot_file = tmp_path / "hot.exe"
        hot_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
        cache.put(str(hot_file), {"type": "hot"})

        for i in range(10):
            cache.get(str(hot_file))
            time.sleep(0.01)

            new_file = tmp_path / f"file_{i}.exe"
            new_file.write_bytes(b"MZ\x90\x00" + bytes([i]) * 100)
            cache.put(str(new_file), {"id": i})

        result = cache.get(str(hot_file))
        assert result is not None
        assert result["type"] == "hot"


class TestCacheOperations:
    def test_cache_removes_specific_entries(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})
        assert analysis_cache.get(str(test_binary_path)) is not None

        removed = analysis_cache.remove(str(test_binary_path))

        assert removed is True
        assert analysis_cache.get(str(test_binary_path)) is None

        removed_again = analysis_cache.remove(str(test_binary_path))
        assert removed_again is False

    def test_cache_removes_with_scan_options(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"scan": "quick"}, "quick")
        analysis_cache.put(str(test_binary_path), {"scan": "deep"}, "deep")

        removed = analysis_cache.remove(str(test_binary_path), "quick")

        assert removed is True
        assert analysis_cache.get(str(test_binary_path), "quick") is None
        assert analysis_cache.get(str(test_binary_path), "deep") is not None

    def test_cache_clears_all_entries(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        for i in range(10):
            binary_path = tmp_path / f"app_{i}.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + bytes([i]) * 100)
            analysis_cache.put(str(binary_path), {"id": i})

        assert analysis_cache.get_stats().total_entries >= 10

        analysis_cache.clear()

        stats = analysis_cache.get_stats()
        assert stats.total_entries == 0
        assert stats.cache_hits == 0
        assert stats.cache_misses == 0


class TestCachePersistence:
    def test_cache_persists_to_disk(
        self,
        temp_cache_dir: Path,
        test_binary_path: Path,
    ) -> None:
        cache1 = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            auto_save=False,
        )
        cache1.put(str(test_binary_path), {"persisted": "data"})
        cache1.save_cache()

        cache2 = AnalysisCache(cache_dir=str(temp_cache_dir))

        result = cache2.get(str(test_binary_path))
        assert result is not None
        assert result["persisted"] == "data"

    def test_cache_loads_existing_cache_on_initialization(
        self,
        temp_cache_dir: Path,
        tmp_path: Path,
    ) -> None:
        cache1 = AnalysisCache(cache_dir=str(temp_cache_dir), auto_save=False)

        for i in range(5):
            binary_path = tmp_path / f"app_{i}.exe"
            binary_path.write_bytes(b"MZ\x90\x00" + bytes([i]) * 100)
            cache1.put(str(binary_path), {"id": i, "protection": f"Prot_{i}"})

        cache1.save_cache()

        cache2 = AnalysisCache(cache_dir=str(temp_cache_dir))

        for i in range(5):
            binary_path = tmp_path / f"app_{i}.exe"
            result = cache2.get(str(binary_path))
            assert result is not None
            assert result["id"] == i
            assert result["protection"] == f"Prot_{i}"

    def test_cache_saves_statistics_to_disk(
        self,
        temp_cache_dir: Path,
        test_binary_path: Path,
    ) -> None:
        cache = AnalysisCache(cache_dir=str(temp_cache_dir), auto_save=False)

        cache.put(str(test_binary_path), {"data": "test"})
        for _ in range(5):
            cache.get(str(test_binary_path))
        for i in range(3):
            cache.get(f"/nonexistent_{i}.exe")

        cache.save_cache()

        stats_file = cache.cache_dir / "cache_stats.json"
        assert stats_file.exists()

        with open(stats_file) as f:
            stats_data = json.load(f)

        assert stats_data["cache_hits"] >= 5
        assert stats_data["cache_misses"] >= 3

    def test_cache_handles_corrupted_cache_file(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache_file = temp_cache_dir / "analysis_cache.pkl"
        cache_file.write_bytes(b"corrupted data")

        cache = AnalysisCache(cache_dir=str(temp_cache_dir))

        assert cache.get_stats().total_entries == 0


class TestCacheKeyGeneration:
    def test_cache_generates_unique_keys_for_different_files(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file1.exe", "")
        key2 = analysis_cache._generate_cache_key("/file2.exe", "")

        assert key1 != key2

    def test_cache_generates_unique_keys_for_different_options(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file.exe", "quick")
        key2 = analysis_cache._generate_cache_key("/file.exe", "deep")

        assert key1 != key2

    def test_cache_generates_consistent_keys(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        key1 = analysis_cache._generate_cache_key("/file.exe", "options")
        key2 = analysis_cache._generate_cache_key("/file.exe", "options")

        assert key1 == key2

    def test_cache_key_includes_file_path(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        file_path = "/path/to/protected_app.exe"
        key = analysis_cache._generate_cache_key(file_path, "")

        assert file_path in key


class TestCacheSizeManagement:
    def test_cache_calculates_size_accurately(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        large_data = {"data": "x" * 10000}

        analysis_cache.put("/file.exe", large_data)

        size_bytes = analysis_cache._calculate_cache_size()
        assert size_bytes > 10000

        size_mb = analysis_cache._get_cache_size_mb()
        assert size_mb > 0

    def test_cache_tracks_total_size_in_stats(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        data1 = {"protection": "VMProtect", "data": "x" * 5000}
        data2 = {"protection": "Themida", "data": "y" * 7000}

        analysis_cache.put("/file1.exe", data1)
        analysis_cache.put("/file2.exe", data2)

        stats = analysis_cache.get_stats()
        assert stats.total_size_bytes > 12000

    def test_cache_handles_very_large_analysis_results(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        huge_data = {
            "protections": ["VMProtect"] * 1000,
            "import_table": {f"dll_{i}": [f"func_{j}" for j in range(100)] for i in range(50)},
            "strings": [f"string_{i}" * 100 for i in range(500)],
            "bytecode": b"\x00" * 100000,
        }

        binary_path = tmp_path / "large_app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        analysis_cache.put(str(binary_path), huge_data)
        result = analysis_cache.get(str(binary_path))

        assert result is not None
        assert len(result["protections"]) == 1000
        assert len(result["import_table"]) == 50
        assert len(result["bytecode"]) == 100000


class TestCacheThreadSafety:
    def test_cache_handles_concurrent_puts(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        def worker(thread_id: int) -> None:
            for i in range(20):
                binary_path = tmp_path / f"thread_{thread_id}_file_{i}.exe"
                binary_path.write_bytes(b"MZ\x90\x00" + bytes([thread_id, i]) * 50)
                analysis_cache.put(
                    str(binary_path),
                    {"thread": thread_id, "index": i},
                )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = analysis_cache.get_stats()
        assert stats.total_entries > 0

    def test_cache_handles_concurrent_gets(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "shared"})

        results = []

        def worker() -> None:
            for _ in range(50):
                result = analysis_cache.get(str(test_binary_path))
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 500
        assert all(r is not None for r in results)
        assert all(r["data"] == "shared" for r in results)

    def test_cache_handles_concurrent_mixed_operations(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        def put_worker(thread_id: int) -> None:
            for i in range(10):
                binary_path = tmp_path / f"put_{thread_id}_{i}.exe"
                binary_path.write_bytes(b"MZ\x90\x00" + bytes([thread_id]) * 100)
                analysis_cache.put(str(binary_path), {"id": i})

        def get_worker(thread_id: int) -> None:
            for i in range(10):
                binary_path = tmp_path / f"put_{thread_id}_{i}.exe"
                analysis_cache.get(str(binary_path))

        put_threads = [threading.Thread(target=put_worker, args=(i,)) for i in range(5)]
        get_threads = [threading.Thread(target=get_worker, args=(i,)) for i in range(5)]

        for t in put_threads + get_threads:
            t.start()
        for t in put_threads + get_threads:
            t.join()

        stats = analysis_cache.get_stats()
        assert stats.total_entries > 0
        assert stats.cache_hits + stats.cache_misses > 0


class TestGlobalCacheInstance:
    def test_get_analysis_cache_returns_singleton(self) -> None:
        cache1 = get_analysis_cache()
        cache2 = get_analysis_cache()

        assert cache1 is cache2

    def test_clear_analysis_cache_resets_global_instance(self) -> None:
        cache1 = get_analysis_cache()
        cache1.put("/test.exe", {"data": "test"})

        clear_analysis_cache()

        cache2 = get_analysis_cache()
        assert cache2 is not cache1
        assert cache2.get("/test.exe") is None


class TestCachePerformance:
    def test_cache_put_performance_many_entries(
        self,
        analysis_cache: AnalysisCache,
    ) -> None:
        start_time = time.time()

        for i in range(100):
            analysis_cache.put(
                f"/file_{i}.exe",
                {"id": i, "protection": "VMProtect", "entropy": 7.8},
            )

        elapsed = time.time() - start_time

        assert elapsed < 5.0
        assert analysis_cache.get_stats().total_entries >= 100

    def test_cache_get_performance_many_accesses(
        self,
        analysis_cache: AnalysisCache,
        test_binary_path: Path,
    ) -> None:
        analysis_cache.put(str(test_binary_path), {"data": "test"})

        start_time = time.time()

        for _ in range(1000):
            analysis_cache.get(str(test_binary_path))

        elapsed = time.time() - start_time

        assert elapsed < 2.0
        stats = analysis_cache.get_stats()
        assert stats.cache_hits >= 1000

    def test_cache_eviction_performance(
        self,
        temp_cache_dir: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=100,
            max_size_mb=10,
            auto_save=False,
        )

        start_time = time.time()

        for i in range(500):
            cache.put(f"/file_{i}.exe", {"id": i, "data": "x" * 1000})

        elapsed = time.time() - start_time

        assert elapsed < 10.0
        assert cache.get_stats().total_entries <= 100


class TestCacheRealWorldScenarios:
    def test_cache_handles_repeated_analysis_of_same_binary(
        self,
        analysis_cache: AnalysisCache,
        real_pe_binary: Path,
        complex_analysis_result: dict[str, Any],
    ) -> None:
        analysis_cache.put(str(real_pe_binary), complex_analysis_result)

        for _ in range(100):
            result = analysis_cache.get(str(real_pe_binary))
            assert result is not None
            assert result["protections"] == complex_analysis_result["protections"]

        stats = analysis_cache.get_stats()
        assert stats.cache_hits >= 100
        assert stats.hit_rate == 100.0

    def test_cache_handles_binary_update_workflow(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        binary_path = tmp_path / "app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 5000)

        v1_analysis = {"version": "1.0", "protection": "VMProtect 3.5"}
        analysis_cache.put(str(binary_path), v1_analysis)

        result = analysis_cache.get(str(binary_path))
        assert result["version"] == "1.0"

        time.sleep(0.1)
        binary_path.write_bytes(b"MZ\x90\x00" + b"\xFF" * 5000)

        result = analysis_cache.get(str(binary_path))
        assert result is None

        v2_analysis = {"version": "2.0", "protection": "Themida 3.1"}
        analysis_cache.put(str(binary_path), v2_analysis)

        result = analysis_cache.get(str(binary_path))
        assert result["version"] == "2.0"

    def test_cache_handles_multiple_scan_modes_workflow(
        self,
        analysis_cache: AnalysisCache,
        real_pe_binary: Path,
    ) -> None:
        quick_scan = {
            "scan_type": "quick",
            "duration_seconds": 1,
            "protections": ["VMProtect"],
        }
        deep_scan = {
            "scan_type": "deep",
            "duration_seconds": 60,
            "protections": ["VMProtect 3.5", "Themida 3.1"],
            "detailed_analysis": {"entropy": 7.95, "packer_layers": 3},
        }
        comprehensive_scan = {
            "scan_type": "comprehensive",
            "duration_seconds": 300,
            "protections": ["VMProtect 3.5", "Themida 3.1", "Code Virtualizer"],
            "license_validation": {"algorithm": "RSA-2048", "key_locations": [0x401000]},
        }

        analysis_cache.put(str(real_pe_binary), quick_scan, "quick")
        analysis_cache.put(str(real_pe_binary), deep_scan, "deep")
        analysis_cache.put(str(real_pe_binary), comprehensive_scan, "comprehensive")

        quick_result = analysis_cache.get(str(real_pe_binary), "quick")
        assert quick_result["duration_seconds"] == 1

        deep_result = analysis_cache.get(str(real_pe_binary), "deep")
        assert deep_result["duration_seconds"] == 60
        assert "detailed_analysis" in deep_result

        comprehensive_result = analysis_cache.get(str(real_pe_binary), "comprehensive")
        assert comprehensive_result["duration_seconds"] == 300
        assert "license_validation" in comprehensive_result

    def test_cache_handles_cache_warming_scenario(
        self,
        analysis_cache: AnalysisCache,
        tmp_path: Path,
    ) -> None:
        common_apps = []
        for i in range(50):
            app_path = tmp_path / f"common_app_{i}.exe"
            app_path.write_bytes(b"MZ\x90\x00" + bytes([i]) * 1000)
            common_apps.append(app_path)

            analysis_cache.put(
                str(app_path),
                {
                    "app_id": i,
                    "protection": "VMProtect" if i % 2 == 0 else "Themida",
                    "license_type": "online" if i % 3 == 0 else "offline",
                },
            )

        hit_count = 0
        for app_path in common_apps:
            result = analysis_cache.get(str(app_path))
            if result is not None:
                hit_count += 1

        assert hit_count >= 45

        stats = analysis_cache.get_stats()
        assert stats.hit_rate >= 85.0

    def test_cache_handles_cache_pressure_scenario(
        self,
        temp_cache_dir: Path,
        tmp_path: Path,
    ) -> None:
        cache = AnalysisCache(
            cache_dir=str(temp_cache_dir),
            max_entries=20,
            max_size_mb=5,
            auto_save=False,
        )

        for i in range(100):
            app_path = tmp_path / f"app_{i}.exe"
            app_path.write_bytes(b"MZ\x90\x00" + bytes([i % 256]) * 500)

            large_analysis = {
                "app_id": i,
                "protections": ["VMProtect", "Themida"],
                "strings": [f"string_{j}" * 50 for j in range(100)],
            }

            cache.put(str(app_path), large_analysis)

        stats = cache.get_stats()
        assert stats.total_entries <= 20

        size_mb = cache._get_cache_size_mb()
        assert size_mb <= 7.0
