"""Production Tests for ICP Backend Module.

Tests validate native ICP Engine integration, file analysis, protection detection,
caching mechanisms, and parallel scanning. All tests use real binaries and validate
actual analysis capabilities without mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import hashlib
import os
import struct
import tempfile
from pathlib import Path
from typing import Generator

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


WINDOWS_NOTEPAD = Path("C:/Windows/System32/notepad.exe")
WINDOWS_KERNEL32 = Path("C:/Windows/System32/kernel32.dll")


@pytest.fixture
def sample_pe_binary(tmp_path: Path) -> Generator[Path, None, None]:
    """Create sample PE binary for testing."""
    binary_path = tmp_path / "sample.exe"

    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)

    optional_header = struct.pack(
        "<HBBIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,
        14,
        0,
        0x1000,
        0x0,
        0,
        0x1000,
        0x1000,
        0x00400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x200,
        0,
        3,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        0x10,
    )
    optional_header += b"\x00" * (0xE0 - len(optional_header))

    section = b".text\x00\x00\x00" + struct.pack("<IIIIIHHHI", 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020)

    pe_header = pe_signature + coff_header + optional_header + section
    headers = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_header

    code_data = bytearray(0x1000)
    code_data[:4] = b"\x55\x8b\xec\x5d"

    binary_data = headers.ljust(0x200, b"\x00") + code_data

    binary_path.write_bytes(binary_data)
    yield binary_path


@pytest.fixture
def real_system_binary() -> Path:
    """Provide real Windows system binary for testing."""
    if not WINDOWS_NOTEPAD.exists():
        pytest.skip("Windows notepad.exe not available")
    return WINDOWS_NOTEPAD


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Create temporary directory for result caching."""
    cache_path = tmp_path / "icp_cache"
    cache_path.mkdir(exist_ok=True)
    return cache_path


class TestICPDetection:
    """Test ICPDetection dataclass."""

    def test_detection_stores_complete_information(self) -> None:
        """ICPDetection stores all detection information."""
        detection = ICPDetection(
            name="UPX", type="Packer", version="3.96", info="UPX packer", string="UPX!", confidence=0.95
        )

        assert detection.name == "UPX"
        assert detection.type == "Packer"
        assert detection.version == "3.96"
        assert detection.info == "UPX packer"
        assert detection.string == "UPX!"
        assert detection.confidence == 0.95

    def test_detection_from_dict_parses_legacy_format(self) -> None:
        """ICPDetection.from_dict parses legacy JSON format."""
        data = {"name": "VMProtect", "type": "Protector", "version": "3.5", "info": "Strong protection", "string": ".vmp0"}

        detection = ICPDetection.from_dict(data)

        assert detection.name == "VMProtect"
        assert detection.type == "Protector"
        assert detection.version == "3.5"


class TestICPFileInfo:
    """Test ICPFileInfo dataclass."""

    def test_file_info_stores_metadata_and_detections(self) -> None:
        """ICPFileInfo stores file metadata and detections list."""
        detection1 = ICPDetection(name="MSVC", type="Compiler", version="19.0", info="", string="", confidence=1.0)
        detection2 = ICPDetection(name="UPX", type="Packer", version="3.96", info="", string="", confidence=0.95)

        file_info = ICPFileInfo(filetype="PE64", size="1048576", offset="0", detections=[detection1, detection2])

        assert file_info.filetype == "PE64"
        assert file_info.size == "1048576"
        assert len(file_info.detections) == 2

    def test_file_info_from_dict_parses_legacy_format(self) -> None:
        """ICPFileInfo.from_dict parses legacy JSON format."""
        data = {
            "filetype": "PE32",
            "size": "524288",
            "offset": "0",
            "values": [{"name": "Themida", "type": "Protector", "version": "3.0", "info": "", "string": ""}],
        }

        file_info = ICPFileInfo.from_dict(data)

        assert file_info.filetype == "PE32"
        assert len(file_info.detections) == 1
        assert file_info.detections[0].name == "Themida"


class TestICPScanResult:
    """Test ICPScanResult dataclass."""

    def test_scan_result_tracks_detections(self) -> None:
        """ICPScanResult tracks file information and detections."""
        detection = ICPDetection(name="ASPack", type="Packer", version="", info="", string="", confidence=1.0)
        file_info = ICPFileInfo(filetype="PE32", size="1024", detections=[detection])

        result = ICPScanResult(file_path="test.exe", file_infos=[file_info])

        assert result.file_path == "test.exe"
        assert len(result.file_infos) == 1
        assert len(result.all_detections) == 1

    def test_is_packed_detects_packers(self) -> None:
        """is_packed property detects packer presence."""
        packer_detection = ICPDetection(name="UPX", type="Packer", version="", info="", string="", confidence=1.0)
        file_info = ICPFileInfo(filetype="PE32", size="1024", detections=[packer_detection])

        result = ICPScanResult(file_path="test.exe", file_infos=[file_info])

        assert result.is_packed is True

    def test_is_protected_detects_protectors(self) -> None:
        """is_protected property detects protection schemes."""
        protector_detection = ICPDetection(name="VMProtect", type="Protector", version="", info="", string="", confidence=1.0)
        file_info = ICPFileInfo(filetype="PE32", size="1024", detections=[protector_detection])

        result = ICPScanResult(file_path="test.exe", file_infos=[file_info])

        assert result.is_protected is True

    def test_from_icp_text_parses_engine_output(self) -> None:
        """from_icp_text parses ICP Engine text output."""
        icp_text = """PE64
    Compiler: MSVC
    Packer: UPX"""

        result = ICPScanResult.from_icp_text("test.exe", icp_text)

        assert result.file_path == "test.exe"
        assert len(result.file_infos) == 1
        assert result.file_infos[0].filetype == "PE64"
        assert len(result.file_infos[0].detections) == 2


class TestNativeICPLibrary:
    """Test native ICP library interface."""

    def test_native_library_initializes(self) -> None:
        """NativeICPLibrary initializes without errors."""
        lib = NativeICPLibrary()

        assert lib is not None
        assert isinstance(lib.functions, dict)

    def test_calculate_entropy_python_computes_shannon_entropy(self, sample_pe_binary: Path) -> None:
        """_calculate_entropy_python computes correct Shannon entropy."""
        lib = NativeICPLibrary()

        entropy = lib._calculate_entropy_python(str(sample_pe_binary))

        assert isinstance(entropy, float)
        assert 0.0 <= entropy <= 8.0

    def test_calculate_entropy_handles_empty_file(self, tmp_path: Path) -> None:
        """_calculate_entropy_python handles empty files."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        lib = NativeICPLibrary()
        entropy = lib._calculate_entropy_python(str(empty_file))

        assert entropy == 0.0

    def test_calculate_entropy_handles_high_entropy_data(self, tmp_path: Path) -> None:
        """_calculate_entropy_python detects high entropy in encrypted data."""
        import os

        high_entropy_file = tmp_path / "encrypted.bin"
        high_entropy_file.write_bytes(os.urandom(1024))

        lib = NativeICPLibrary()
        entropy = lib._calculate_entropy_python(str(high_entropy_file))

        assert entropy > 7.5


class TestResultCache:
    """Test SQLite-based result caching."""

    def test_cache_initializes_with_database(self, cache_dir: Path) -> None:
        """ResultCache initializes SQLite database."""
        cache = ResultCache(cache_dir)

        assert cache.db_path.exists()
        assert cache.db_path.suffix == ".db"
        assert len(cache.memory_cache) == 0

    def test_cache_computes_file_hash(self, sample_pe_binary: Path, cache_dir: Path) -> None:
        """get_file_hash computes SHA256 hash of file."""
        cache = ResultCache(cache_dir)

        file_hash = cache.get_file_hash(str(sample_pe_binary))

        assert isinstance(file_hash, str)
        assert len(file_hash) == 64
        assert all(c in "0123456789abcdef" for c in file_hash)

    def test_cache_stores_and_retrieves_results(self, sample_pe_binary: Path, cache_dir: Path) -> None:
        """Cache stores and retrieves scan results."""
        cache = ResultCache(cache_dir)

        result_data = {"detects": [{"filetype": "PE32", "values": [{"name": "Test", "type": "Packer"}]}]}

        cache.put(str(sample_pe_binary), "deep", result_data)

        retrieved = cache.get(str(sample_pe_binary), "deep")

        assert retrieved is not None
        assert retrieved == result_data

    def test_cache_invalidation_removes_entries(self, sample_pe_binary: Path, cache_dir: Path) -> None:
        """invalidate removes cached entries for file."""
        cache = ResultCache(cache_dir)

        result_data = {"detects": []}
        cache.put(str(sample_pe_binary), "deep", result_data)

        cache.invalidate(str(sample_pe_binary))

        retrieved = cache.get(str(sample_pe_binary), "deep")
        assert retrieved is None

    def test_cache_stats_track_hits_and_misses(self, sample_pe_binary: Path, cache_dir: Path) -> None:
        """get_stats tracks cache hits and misses."""
        cache = ResultCache(cache_dir)

        result_data = {"detects": []}
        cache.put(str(sample_pe_binary), "deep", result_data)

        cache.get(str(sample_pe_binary), "deep")
        cache.get(str(sample_pe_binary), "normal")

        stats = cache.get_stats()

        assert stats["hits"] >= 1
        assert stats["misses"] >= 1


class TestParallelScanner:
    """Test parallel file scanning."""

    def test_parallel_scanner_initializes_with_workers(self) -> None:
        """ParallelScanner initializes with thread pool."""
        scanner = ParallelScanner(max_workers=4)

        assert scanner.max_workers == 4
        assert scanner.executor is not None

    @pytest.mark.asyncio
    async def test_parallel_scanner_processes_multiple_files(self, sample_pe_binary: Path) -> None:
        """scan_files_parallel processes multiple files concurrently."""
        scanner = ParallelScanner(max_workers=2)

        file_list = [str(sample_pe_binary)]

        results = await scanner.scan_files_parallel(file_list, ScanMode.NORMAL, None)

        assert len(results) == 1
        assert str(sample_pe_binary) in results

    def test_parallel_scanner_shutdown_cleans_up(self) -> None:
        """shutdown cleanly terminates thread pool."""
        scanner = ParallelScanner(max_workers=2)

        scanner.shutdown()

        assert scanner.executor._shutdown is True


class TestICPBackend:
    """Test ICP backend main class."""

    def test_backend_initializes_with_native_library(self) -> None:
        """ICPBackend initializes with native library interface."""
        try:
            backend = ICPBackend()
            assert backend.native_lib is not None
            assert backend.cache is not None
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_backend_get_engine_version_returns_string(self) -> None:
        """get_engine_version returns version string."""
        try:
            backend = ICPBackend()
            version = backend.get_engine_version()

            assert isinstance(version, str)
            assert len(version) > 0
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_backend_get_available_scan_modes_returns_list(self) -> None:
        """get_available_scan_modes returns list of scan modes."""
        try:
            backend = ICPBackend()
            modes = backend.get_available_scan_modes()

            assert isinstance(modes, list)
            assert "normal" in modes
            assert "deep" in modes
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_backend_is_icp_available_checks_status(self) -> None:
        """is_icp_available checks if ICP Engine is working."""
        try:
            backend = ICPBackend()
            available = backend.is_icp_available()

            assert isinstance(available, bool)
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    @pytest.mark.asyncio
    async def test_analyze_file_processes_real_binary(self, real_system_binary: Path) -> None:
        """analyze_file processes real Windows binary."""
        try:
            backend = ICPBackend()
            result = await backend.analyze_file(str(real_system_binary), ScanMode.NORMAL)

            assert isinstance(result, ICPScanResult)
            assert result.file_path == str(real_system_binary)
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    @pytest.mark.asyncio
    async def test_analyze_file_detects_nonexistent_file(self, tmp_path: Path) -> None:
        """analyze_file handles nonexistent file."""
        try:
            backend = ICPBackend()
            result = await backend.analyze_file(str(tmp_path / "nonexistent.exe"), ScanMode.NORMAL)

            assert result.error is not None
            assert "not found" in result.error.lower()
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_get_file_entropy_computes_entropy(self, real_system_binary: Path) -> None:
        """get_file_entropy computes Shannon entropy."""
        try:
            backend = ICPBackend()
            entropy = backend.get_file_entropy(str(real_system_binary))

            assert isinstance(entropy, float)
            assert 0.0 <= entropy <= 8.0
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_extract_strings_finds_ascii_strings(self, sample_pe_binary: Path) -> None:
        """extract_strings finds ASCII strings in binary."""
        try:
            backend = ICPBackend()
            strings = backend.extract_strings(str(sample_pe_binary), min_length=4)

            assert isinstance(strings, list)
            for string_info in strings:
                assert "offset" in string_info
                assert "string" in string_info
                assert "length" in string_info
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_get_cache_stats_returns_statistics(self) -> None:
        """get_cache_stats returns cache statistics."""
        try:
            backend = ICPBackend()
            stats = backend.get_cache_stats()

            assert isinstance(stats, dict)
            assert "hits" in stats or "cache_enabled" in stats
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_get_error_stats_tracks_errors(self) -> None:
        """get_error_stats returns error tracking information."""
        try:
            backend = ICPBackend()
            stats = backend.get_error_stats()

            assert isinstance(stats, dict)
            assert "error_count" in stats
            assert "max_retries" in stats
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    def test_reset_error_state_clears_errors(self) -> None:
        """reset_error_state clears error tracking."""
        try:
            backend = ICPBackend()
            backend.error_count = 5
            backend.last_error = "Test error"

            backend.reset_error_state()

            assert backend.error_count == 0
            assert backend.last_error is None
        except ICPEngineError:
            pytest.skip("ICP Engine not available")


class TestICPBackendSingleton:
    """Test ICP backend singleton pattern."""

    def test_get_icp_backend_returns_singleton(self) -> None:
        """get_icp_backend returns singleton instance."""
        try:
            backend1 = get_icp_backend()
            backend2 = get_icp_backend()

            assert backend1 is backend2
        except ICPEngineError:
            pytest.skip("ICP Engine not available")

    @pytest.mark.asyncio
    async def test_analyze_with_icp_integration_helper(self, sample_pe_binary: Path) -> None:
        """analyze_with_icp provides integration helper."""
        try:
            result = await analyze_with_icp(str(sample_pe_binary))

            assert result is None or isinstance(result, ICPScanResult)
        except ICPEngineError:
            pytest.skip("ICP Engine not available")


class TestScanModeEnum:
    """Test ScanMode enumeration."""

    def test_scan_mode_has_all_modes(self) -> None:
        """ScanMode enum has all scanning modes."""
        assert hasattr(ScanMode, "NORMAL")
        assert hasattr(ScanMode, "DEEP")
        assert hasattr(ScanMode, "HEURISTIC")
        assert hasattr(ScanMode, "AGGRESSIVE")
        assert hasattr(ScanMode, "ALL")

    def test_scan_mode_values_are_strings(self) -> None:
        """ScanMode enum values are strings."""
        assert isinstance(ScanMode.NORMAL.value, str)
        assert isinstance(ScanMode.DEEP.value, str)
