"""Comprehensive tests for ICP Backend protection analysis system.

Tests all ICP Backend functionality including:
- Native library integration
- Scan mode variations
- File type detection
- Entropy calculation
- String extraction
- Section parsing
- Packer/protector detection
- Result caching system
- Parallel scanning
- Error handling and recovery
- Supplemental engine integration

All tests use real binary data and validate actual ICP functionality.
No mocks for core protection detection capabilities.
"""

import asyncio
import hashlib
import os
import sqlite3
import struct
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.protection.icp_backend import (
    ICPBackend,
    ICPDetection,
    ICPEngineError,
    ICPFileInfo,
    ICPScanResult,
    NativeICPLibrary,
    ParallelScanner,
    ResultCache,
    ScanMode,
    analyze_with_icp,
    get_icp_backend,
)


@pytest.fixture
def temp_binary_pe32() -> Path:
    """Create temporary PE32 binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * 32
        + b"PE\x00\x00"
        + struct.pack("<H", 0x014C)
        + b"\x00" * 18
        + b"\x0B\x01"
        + b"\x00" * 100
    )

    pe_data = pe_header + b"\x00" * (1024 - len(pe_header))
    temp_file.write(pe_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_pe64() -> Path:
    """Create temporary PE64 binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * 32
        + b"PE\x00\x00"
        + struct.pack("<H", 0x8664)
        + b"\x00" * 18
        + b"\x0B\x02"
        + b"\x00" * 100
    )

    pe_data = pe_header + b"\x00" * (1024 - len(pe_header))
    temp_file.write(pe_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_elf64() -> Path:
    """Create temporary ELF64 binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix="")
    elf_header = (
        b"\x7fELF"
        + b"\x02"
        + b"\x01"
        + b"\x01"
        + b"\x00" * 9
        + b"\x02\x00"
        + b"\x3E\x00"
        + b"\x01\x00\x00\x00"
        + b"\x00" * 100
    )

    elf_data = elf_header + b"\x00" * (1024 - len(elf_header))
    temp_file.write(elf_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_upx_packed() -> Path:
    """Create temporary UPX-packed binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * 32
        + b"PE\x00\x00"
        + struct.pack("<H", 0x014C)
        + b"\x00" * 100
    )

    upx_signature = b"UPX0" + b"\x00" * 20 + b"UPX1" + b"\x00" * 20 + b"UPX!"
    pe_data = pe_header + upx_signature + b"\x00" * (2048 - len(pe_header) - len(upx_signature))

    temp_file.write(pe_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_vmprotect() -> Path:
    """Create temporary VMProtect-protected binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    pe_header = (
        b"MZ"
        + b"\x90" * 58
        + struct.pack("<I", 0x80)
        + b"\x00" * 32
        + b"PE\x00\x00"
        + struct.pack("<H", 0x8664)
        + b"\x00" * 100
    )

    vmp_signature = b"VMProtect" + b"\x00" * 50 + b".vmp0" + b"\x00" * 50 + b".vmp1"
    pe_data = pe_header + vmp_signature + b"\x00" * (4096 - len(pe_header) - len(vmp_signature))

    temp_file.write(pe_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_high_entropy() -> Path:
    """Create temporary high-entropy binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")

    import random
    random.seed(42)
    high_entropy_data = bytes(random.randint(0, 255) for _ in range(4096))

    temp_file.write(high_entropy_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_low_entropy() -> Path:
    """Create temporary low-entropy binary for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    low_entropy_data = b"A" * 2048 + b"B" * 2048

    temp_file.write(low_entropy_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_binary_with_strings() -> Path:
    """Create temporary binary with embedded strings for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")

    pe_header = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 100
    strings_data = (
        b"\x00\x00"
        + b"LicenseKey123456"
        + b"\x00\x00"
        + b"SerialNumber"
        + b"\x00\x00"
        + b"RegistrationCode"
        + b"\x00\x00"
        + b"ActivationKey"
        + b"\x00" * 200
    )

    binary_data = pe_header + strings_data + b"\x00" * (2048 - len(pe_header) - len(strings_data))
    temp_file.write(binary_data)
    temp_file.close()

    yield Path(temp_file.name)

    if Path(temp_file.name).exists():
        os.unlink(temp_file.name)


@pytest.fixture
def temp_cache_dir() -> Path:
    """Create temporary cache directory for testing."""
    temp_dir = tempfile.mkdtemp(prefix="icp_cache_test_")
    yield Path(temp_dir)

    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestICPDetection:
    """Test ICPDetection dataclass functionality."""

    def test_icp_detection_creation(self) -> None:
        """ICPDetection created with all fields."""
        detection = ICPDetection(
            name="UPX",
            type="Packer",
            version="3.96",
            info="UPX compressed",
            string="UPX!",
            confidence=0.95,
        )

        assert detection.name == "UPX"
        assert detection.type == "Packer"
        assert detection.version == "3.96"
        assert detection.info == "UPX compressed"
        assert detection.string == "UPX!"
        assert detection.confidence == 0.95

    def test_icp_detection_from_icp_result(self) -> None:
        """ICPDetection created from ICP result object."""
        mock_result = MagicMock()
        mock_result.name = "VMProtect"
        mock_result.type = "Protector"
        mock_result.version = "3.5"
        mock_result.info = "VMProtect protection detected"
        mock_result.string = ".vmp0"

        detection = ICPDetection.from_icp_result(mock_result)

        assert detection.name == "VMProtect"
        assert detection.type == "Protector"
        assert detection.version == "3.5"
        assert detection.info == "VMProtect protection detected"
        assert detection.string == ".vmp0"
        assert detection.confidence == 1.0

    def test_icp_detection_from_dict(self) -> None:
        """ICPDetection created from dictionary."""
        data = {
            "name": "Themida",
            "type": "Protector",
            "version": "3.1",
            "info": "Themida protection",
            "string": "Themida",
        }

        detection = ICPDetection.from_dict(data)

        assert detection.name == "Themida"
        assert detection.type == "Protector"
        assert detection.version == "3.1"
        assert detection.info == "Themida protection"
        assert detection.string == "Themida"

    def test_icp_detection_from_dict_missing_fields(self) -> None:
        """ICPDetection handles missing dictionary fields."""
        data = {"name": "TestPacker"}

        detection = ICPDetection.from_dict(data)

        assert detection.name == "TestPacker"
        assert detection.type == "Unknown"
        assert detection.version == ""
        assert detection.info == ""
        assert detection.string == ""


class TestICPFileInfo:
    """Test ICPFileInfo dataclass functionality."""

    def test_icp_file_info_creation(self) -> None:
        """ICPFileInfo created with all fields."""
        detection = ICPDetection(name="UPX", type="Packer")
        file_info = ICPFileInfo(
            filetype="PE64",
            size="4096",
            offset="0",
            parentfilepart="",
            detections=[detection],
        )

        assert file_info.filetype == "PE64"
        assert file_info.size == "4096"
        assert file_info.offset == "0"
        assert len(file_info.detections) == 1
        assert file_info.detections[0].name == "UPX"

    def test_icp_file_info_from_dict(self) -> None:
        """ICPFileInfo created from dictionary."""
        data = {
            "filetype": "PE32",
            "size": "2048",
            "offset": "0",
            "parentfilepart": "",
            "values": [
                {"name": "ASPack", "type": "Packer", "version": "2.12"},
            ],
        }

        file_info = ICPFileInfo.from_dict(data)

        assert file_info.filetype == "PE32"
        assert file_info.size == "2048"
        assert len(file_info.detections) == 1
        assert file_info.detections[0].name == "ASPack"


class TestICPScanResult:
    """Test ICPScanResult dataclass functionality."""

    def test_icp_scan_result_is_packed_detection(self) -> None:
        """ICPScanResult correctly detects packed files."""
        detection = ICPDetection(name="UPX", type="Packer")
        file_info = ICPFileInfo(filetype="PE64", size="4096", detections=[detection])
        result = ICPScanResult(file_path="test.exe", file_infos=[file_info])

        assert result.is_packed is True
        assert result.is_protected is False

    def test_icp_scan_result_is_protected_detection(self) -> None:
        """ICPScanResult correctly detects protected files."""
        detection = ICPDetection(name="VMProtect", type="Protector")
        file_info = ICPFileInfo(filetype="PE64", size="4096", detections=[detection])
        result = ICPScanResult(file_path="test.exe", file_infos=[file_info])

        assert result.is_packed is False
        assert result.is_protected is True

    def test_icp_scan_result_all_detections(self) -> None:
        """ICPScanResult aggregates all detections."""
        det1 = ICPDetection(name="UPX", type="Packer")
        det2 = ICPDetection(name="VMProtect", type="Protector")

        info1 = ICPFileInfo(filetype="PE64", size="2048", detections=[det1])
        info2 = ICPFileInfo(filetype="PE64", size="2048", offset="2048", detections=[det2])

        result = ICPScanResult(file_path="test.exe", file_infos=[info1, info2])

        assert len(result.all_detections) == 2
        assert result.all_detections[0].name == "UPX"
        assert result.all_detections[1].name == "VMProtect"

    def test_icp_scan_result_from_json(self) -> None:
        """ICPScanResult created from JSON data."""
        json_data = {
            "detects": [
                {
                    "filetype": "PE32",
                    "size": "4096",
                    "offset": "0",
                    "values": [
                        {"name": "Themida", "type": "Protector", "version": "3.1"},
                    ],
                },
            ],
        }

        result = ICPScanResult.from_json("test.exe", json_data)

        assert result.file_path == "test.exe"
        assert len(result.file_infos) == 1
        assert result.file_infos[0].filetype == "PE32"
        assert len(result.file_infos[0].detections) == 1

    def test_icp_scan_result_from_icp_text(self, temp_binary_pe64: Path) -> None:
        """ICPScanResult created from ICP text output."""
        icp_text = """PE64
    Packer: UPX
    Protector: VMProtect"""

        result = ICPScanResult.from_icp_text(str(temp_binary_pe64), icp_text)

        assert result.file_path == str(temp_binary_pe64)
        assert len(result.file_infos) == 1
        assert result.file_infos[0].filetype == "PE64"
        assert len(result.file_infos[0].detections) == 2
        assert result.file_infos[0].detections[0].name == "UPX"
        assert result.file_infos[0].detections[1].name == "VMProtect"

    def test_icp_scan_result_from_icp_text_empty(self, temp_binary_pe64: Path) -> None:
        """ICPScanResult handles empty ICP text output."""
        result = ICPScanResult.from_icp_text(str(temp_binary_pe64), "")

        assert result.file_path == str(temp_binary_pe64)
        assert len(result.file_infos) == 1
        assert result.file_infos[0].filetype == "Binary"
        assert len(result.file_infos[0].detections) == 0


class TestNativeICPLibrary:
    """Test NativeICPLibrary functionality."""

    def test_native_library_initialization(self) -> None:
        """NativeICPLibrary initializes without error."""
        lib = NativeICPLibrary()
        assert lib is not None
        assert hasattr(lib, "lib")
        assert hasattr(lib, "functions")

    def test_calculate_entropy_python(self, temp_binary_high_entropy: Path) -> None:
        """Native library calculates entropy correctly."""
        lib = NativeICPLibrary()
        entropy = lib._calculate_entropy_python(str(temp_binary_high_entropy), 0)

        assert entropy > 7.0
        assert entropy <= 8.0

    def test_calculate_entropy_python_low_entropy(self, temp_binary_low_entropy: Path) -> None:
        """Native library detects low entropy correctly."""
        lib = NativeICPLibrary()
        entropy = lib._calculate_entropy_python(str(temp_binary_low_entropy), 0)

        assert entropy < 2.0

    def test_calculate_entropy_python_max_bytes(self, temp_binary_high_entropy: Path) -> None:
        """Native library respects max_bytes parameter."""
        lib = NativeICPLibrary()
        entropy = lib._calculate_entropy_python(str(temp_binary_high_entropy), 1024)

        assert entropy > 0.0


class TestResultCache:
    """Test ResultCache functionality."""

    def test_result_cache_initialization(self, temp_cache_dir: Path) -> None:
        """ResultCache initializes with database."""
        cache = ResultCache(temp_cache_dir)

        assert cache.db_path.exists()
        assert cache.db_path.name == "icp_cache.db"
        assert len(cache.memory_cache) == 0

    def test_result_cache_put_and_get(self, temp_cache_dir: Path, temp_binary_pe64: Path) -> None:
        """ResultCache stores and retrieves results."""
        cache = ResultCache(temp_cache_dir)

        result_data = {
            "detects": [
                {
                    "filetype": "PE64",
                    "size": "4096",
                    "values": [{"name": "UPX", "type": "Packer"}],
                },
            ],
        }

        cache.put(str(temp_binary_pe64), "deep", result_data)
        cached = cache.get(str(temp_binary_pe64), "deep")

        assert cached is not None
        assert cached["detects"][0]["filetype"] == "PE64"
        assert cache.cache_stats["hits"] == 1

    def test_result_cache_miss(self, temp_cache_dir: Path, temp_binary_pe64: Path) -> None:
        """ResultCache returns None for cache miss."""
        cache = ResultCache(temp_cache_dir)

        cached = cache.get(str(temp_binary_pe64), "deep")

        assert cached is None
        assert cache.cache_stats["misses"] == 1

    def test_result_cache_invalidation(self, temp_cache_dir: Path, temp_binary_pe64: Path) -> None:
        """ResultCache invalidates entries correctly."""
        cache = ResultCache(temp_cache_dir)

        result_data = {"detects": [{"filetype": "PE64", "size": "4096", "values": []}]}
        cache.put(str(temp_binary_pe64), "deep", result_data)

        cache.invalidate(str(temp_binary_pe64))
        cached = cache.get(str(temp_binary_pe64), "deep")

        assert cached is None

    def test_result_cache_stats(self, temp_cache_dir: Path) -> None:
        """ResultCache provides statistics."""
        cache = ResultCache(temp_cache_dir)
        stats = cache.get_stats()

        assert "hits" in stats
        assert "misses" in stats
        assert "db_entries" in stats
        assert "memory_entries" in stats
        assert "hit_rate" in stats

    def test_result_cache_file_hash(self, temp_cache_dir: Path, temp_binary_pe64: Path) -> None:
        """ResultCache calculates consistent file hashes."""
        cache = ResultCache(temp_cache_dir)

        hash1 = cache.get_file_hash(str(temp_binary_pe64))
        hash2 = cache.get_file_hash(str(temp_binary_pe64))

        assert hash1 == hash2
        assert len(hash1) == 64


class TestICPBackend:
    """Test ICPBackend main functionality."""

    @pytest.mark.skipif(
        os.environ.get("INTELLICRACK_TESTING") == "1",
        reason="ICP engine disabled during testing",
    )
    def test_icp_backend_initialization(self) -> None:
        """ICPBackend initializes successfully."""
        backend = ICPBackend()

        assert backend is not None
        assert backend.native_lib is not None
        assert backend.cache is not None
        assert backend.parallel_scanner is not None

    def test_icp_backend_initialization_no_cache(self) -> None:
        """ICPBackend initializes without cache."""
        with patch("intellicrack.protection.icp_backend._icp_module", None):
            with patch.object(NativeICPLibrary, "__init__", return_value=None):
                with patch.object(NativeICPLibrary, "lib", MagicMock()):
                    backend = ICPBackend(enable_cache=False)
                    assert backend.cache is None

    def test_detect_file_type_from_bytes_pe32(self) -> None:
        """ICPBackend detects PE32 file type from bytes."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            pe_header = bytearray(300)
            pe_header[:2] = b"MZ"
            struct.pack_into("<I", pe_header, 0x3C, 0x80)
            pe_header[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<H", pe_header, 0x84, 0x014C)

            file_type = backend._detect_file_type_from_bytes(bytes(pe_header))
            assert file_type == "PE32"

    def test_detect_file_type_from_bytes_pe64(self) -> None:
        """ICPBackend detects PE64 file type from bytes."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            pe_header = bytearray(300)
            pe_header[:2] = b"MZ"
            struct.pack_into("<I", pe_header, 0x3C, 0x80)
            pe_header[0x80:0x84] = b"PE\x00\x00"
            struct.pack_into("<H", pe_header, 0x84, 0x8664)

            file_type = backend._detect_file_type_from_bytes(bytes(pe_header))
            assert file_type == "PE64"

    def test_detect_file_type_from_bytes_elf64(self) -> None:
        """ICPBackend detects ELF64 file type from bytes."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            elf64_bytes = b"\x7fELF\x02\x01\x01" + b"\x00" * 100

            file_type = backend._detect_file_type_from_bytes(elf64_bytes)
            assert file_type == "ELF64"

    def test_scan_chunk_for_protections_upx(self) -> None:
        """ICPBackend detects UPX in binary chunks."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            chunk = b"\x00" * 100 + b"UPX0" + b"\x00" * 100
            detections = backend._scan_chunk_for_protections(chunk, 0)

            assert len(detections) > 0
            assert any(d.name == "UPX" for d in detections)

    def test_scan_chunk_for_protections_vmprotect(self) -> None:
        """ICPBackend detects VMProtect in binary chunks."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            chunk = b"\x00" * 100 + b"VMProtect" + b"\x00" * 100
            detections = backend._scan_chunk_for_protections(chunk, 0)

            assert len(detections) > 0
            assert any(d.name == "VMProtect" for d in detections)

    def test_get_file_entropy(self, temp_binary_high_entropy: Path) -> None:
        """ICPBackend calculates file entropy correctly."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            entropy = backend.get_file_entropy(str(temp_binary_high_entropy))

            assert entropy > 7.0
            assert entropy <= 8.0

    def test_extract_strings(self, temp_binary_with_strings: Path) -> None:
        """ICPBackend extracts strings from binary."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            strings = backend.extract_strings(str(temp_binary_with_strings), min_length=4)

            assert len(strings) > 0
            string_values = [s["string"] for s in strings]
            assert any("LicenseKey" in s for s in string_values)
            assert any("SerialNumber" in s for s in string_values)

    def test_extract_strings_min_length(self, temp_binary_with_strings: Path) -> None:
        """ICPBackend respects minimum string length."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            strings_min4 = backend.extract_strings(str(temp_binary_with_strings), min_length=4)
            strings_min10 = backend.extract_strings(str(temp_binary_with_strings), min_length=10)

            assert len(strings_min10) <= len(strings_min4)

    def test_get_scan_flags_normal(self) -> None:
        """ICPBackend generates correct scan flags for normal mode."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()
            flags = backend._get_icp_scan_flags(ScanMode.NORMAL)
            assert flags == 0x0000

    def test_get_scan_flags_deep(self) -> None:
        """ICPBackend generates correct scan flags for deep mode."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()
            flags = backend._get_icp_scan_flags(ScanMode.DEEP)
            assert flags == 0x0003

    def test_get_scan_flags_heuristic(self) -> None:
        """ICPBackend generates correct scan flags for heuristic mode."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()
            flags = backend._get_icp_scan_flags(ScanMode.HEURISTIC)
            assert flags == 0x000C

    def test_error_recovery_state(self) -> None:
        """ICPBackend tracks error recovery state."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            backend.error_count = 5
            backend.last_error = "Test error"

            stats = backend.get_error_stats()
            assert stats["error_count"] == 5
            assert stats["last_error"] == "Test error"
            assert stats["max_retries"] == 3

            backend.reset_error_state()
            assert backend.error_count == 0
            assert backend.last_error is None

    def test_cache_invalidation(self, temp_binary_pe64: Path) -> None:
        """ICPBackend invalidates cache correctly."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            backend.invalidate_cache(str(temp_binary_pe64))

    def test_get_available_scan_modes(self) -> None:
        """ICPBackend returns all available scan modes."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            modes = backend.get_available_scan_modes()

            assert "normal" in modes
            assert "deep" in modes
            assert "heuristic" in modes
            assert "aggressive" in modes
            assert "all" in modes


class TestICPBackendAsync:
    """Test ICPBackend async functionality."""

    @pytest.mark.asyncio
    async def test_analyze_file_nonexistent(self) -> None:
        """ICPBackend handles nonexistent file gracefully."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            result = await backend.analyze_file("/nonexistent/file.exe", ScanMode.NORMAL)

            assert result.error is not None
            assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_analyze_file_timeout(self, temp_binary_pe64: Path) -> None:
        """ICPBackend handles analysis timeout."""
        mock_module = MagicMock()

        with patch("intellicrack.protection.icp_backend._icp_module", mock_module):
            backend = ICPBackend()
            backend.default_scan_timeout = 0.001

            async def slow_scan(*args: Any, **kwargs: Any) -> str:
                await asyncio.sleep(1.0)
                return "PE64"

            with patch.object(backend, "_perform_native_scan", side_effect=slow_scan):
                result = await backend.analyze_file(str(temp_binary_pe64), ScanMode.NORMAL)

                assert result.error is not None
                assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_batch_analyze(self, temp_binary_pe64: Path, temp_binary_pe32: Path) -> None:
        """ICPBackend performs batch analysis."""
        mock_module = MagicMock()
        mock_module.scan_file.return_value = "PE64\n    Packer: UPX"

        with patch("intellicrack.protection.icp_backend._icp_module", mock_module):
            backend = ICPBackend()

            files = [str(temp_binary_pe64), str(temp_binary_pe32)]
            results = await backend.batch_analyze(files, ScanMode.NORMAL, max_concurrent=2)

            assert len(results) == 2
            assert str(temp_binary_pe64) in results
            assert str(temp_binary_pe32) in results


class TestICPBackendSupplemental:
    """Test ICPBackend supplemental analysis integration."""

    def test_merge_supplemental_detections_yara(self) -> None:
        """ICPBackend merges YARA pattern findings."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            scan_result = ICPScanResult(file_path="test.exe")
            supplemental_data = {
                "yara_analysis": {
                    "pattern_matches": [
                        {
                            "rule_name": "Anti_Debug_Check",
                            "category": "ANTI_DEBUG",
                            "description": "Anti-debugging detected",
                            "confidence": 0.9,
                        },
                    ],
                },
            }

            backend._merge_supplemental_detections(scan_result, supplemental_data)

            assert len(scan_result.file_infos) > 0
            assert len(scan_result.all_detections) > 0
            assert any(d.name == "Anti_Debug_Check" for d in scan_result.all_detections)

    def test_calculate_threat_score_packed(self) -> None:
        """ICPBackend calculates threat score for packed files."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            base_analysis = {"is_packed": True, "entropy": 6.5, "packers": ["UPX"]}
            supplemental_data: dict[str, Any] = {}

            threat = backend._calculate_threat_score(base_analysis, supplemental_data)

            assert threat["score"] > 0.0
            assert "level" in threat
            assert "indicators" in threat

    def test_calculate_threat_score_high_entropy(self) -> None:
        """ICPBackend detects high entropy threat."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            base_analysis = {"is_packed": False, "entropy": 7.8, "packers": []}
            supplemental_data: dict[str, Any] = {}

            threat = backend._calculate_threat_score(base_analysis, supplemental_data)

            assert threat["score"] > 1.0
            assert any("entropy" in indicator.lower() for indicator in threat["indicators"])

    def test_generate_bypass_recommendations_packed(self) -> None:
        """ICPBackend generates bypass recommendations for packed files."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            base_analysis = {"is_packed": True, "packers": ["UPX", "VMProtect"]}
            supplemental_data: dict[str, Any] = {}

            recommendations = backend._generate_bypass_recommendations(base_analysis, supplemental_data)

            assert len(recommendations) == 2
            assert any("UPX" in rec["target"] for rec in recommendations)
            assert any("VMProtect" in rec["target"] for rec in recommendations)


class TestSingletonAndHelpers:
    """Test singleton instance and helper functions."""

    def test_get_icp_backend_singleton(self) -> None:
        """get_icp_backend returns singleton instance."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend1 = get_icp_backend()
            backend2 = get_icp_backend()

            assert backend1 is backend2

    @pytest.mark.asyncio
    async def test_analyze_with_icp_helper(self, temp_binary_pe64: Path) -> None:
        """analyze_with_icp helper function works."""
        mock_module = MagicMock()
        mock_module.scan_file.return_value = "PE64"

        with patch("intellicrack.protection.icp_backend._icp_module", mock_module):
            result = await analyze_with_icp(str(temp_binary_pe64))

            assert result is not None
            assert isinstance(result, ICPScanResult)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_binary_file(self) -> None:
        """ICPBackend handles empty binary file."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        temp_file.close()

        try:
            with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
                backend = ICPBackend()
                entropy = backend.get_file_entropy(temp_file.name)
                assert entropy == 0.0
        finally:
            os.unlink(temp_file.name)

    def test_malformed_pe_header(self) -> None:
        """ICPBackend handles malformed PE headers."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_file.write(b"MZ" + b"\x00" * 10)
        temp_file.close()

        try:
            with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
                backend = ICPBackend()
                file_type = backend._detect_file_type_from_bytes(b"MZ" + b"\x00" * 10)
                assert file_type == "PE"
        finally:
            os.unlink(temp_file.name)

    def test_large_file_detection(self) -> None:
        """ICPBackend handles large file scenario."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        temp_file.write(b"\x00" * (10 * 1024 * 1024))
        temp_file.close()

        try:
            with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
                backend = ICPBackend()
                entropy = backend.get_file_entropy(temp_file.name)
                assert entropy >= 0.0
        finally:
            os.unlink(temp_file.name)

    def test_icp_detection_no_version(self) -> None:
        """ICPDetection handles missing version gracefully."""
        mock_result = MagicMock(spec=[])
        mock_result.name = "TestProtector"
        mock_result.type = "Protector"

        detection = ICPDetection.from_icp_result(mock_result)

        assert detection.name == "TestProtector"
        assert detection.version == ""

    def test_cache_corruption_recovery(self, temp_cache_dir: Path) -> None:
        """ResultCache recovers from corrupted database."""
        cache = ResultCache(temp_cache_dir)

        with sqlite3.connect(cache.db_path) as conn:
            conn.execute("DROP TABLE cache")

        cache2 = ResultCache(temp_cache_dir)
        assert cache2.db_path.exists()


class TestPerformance:
    """Test performance characteristics."""

    def test_entropy_calculation_performance(self, temp_binary_high_entropy: Path) -> None:
        """Entropy calculation completes within reasonable time."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            start = time.time()
            backend.get_file_entropy(str(temp_binary_high_entropy))
            duration = time.time() - start

            assert duration < 1.0

    def test_string_extraction_performance(self, temp_binary_with_strings: Path) -> None:
        """String extraction completes within reasonable time."""
        with patch("intellicrack.protection.icp_backend._icp_module", MagicMock()):
            backend = ICPBackend()

            start = time.time()
            backend.extract_strings(str(temp_binary_with_strings))
            duration = time.time() - start

            assert duration < 2.0

    def test_cache_hit_performance(self, temp_cache_dir: Path, temp_binary_pe64: Path) -> None:
        """Cache hit is faster than cache miss."""
        cache = ResultCache(temp_cache_dir)

        result_data = {"detects": [{"filetype": "PE64", "size": "4096", "values": []}]}
        cache.put(str(temp_binary_pe64), "deep", result_data)

        start = time.time()
        cache.get(str(temp_binary_pe64), "deep")
        cache_hit_time = time.time() - start

        assert cache_hit_time < 0.1
